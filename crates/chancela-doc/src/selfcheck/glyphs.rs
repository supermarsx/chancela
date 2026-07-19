//! Glyph-level `/ToUnicode` correctness and font-program integrity — the substance of PDF/A-2**U**.
//!
//! The write-time gate used to assert that a `/ToUnicode` CMap *exists*. That is the letter of the
//! rule and none of its point: the "u" in 2u means text can be reliably extracted, and a CMap that
//! is present but maps the wrong scalars extracts the wrong text while passing every presence
//! check. This module closes that gap for the glyphs the document actually shows, which is
//! tractable precisely because the writer controls the font: one embedded face, Identity-H, one
//! glyph id per code point.
//!
//! Five things are asserted, each of which can fail independently:
//!
//! 1. **Every shown glyph is mapped.** Glyph ids are recovered from the content streams by
//!    tokenizing text-showing operands, not by trusting the writer's bookkeeping.
//! 2. **The mapping round-trips through the embedded font.** For each `(gid, scalar)` pair the
//!    embedded `cmap` must map `scalar` back to `gid`. This is what makes the check meaningful
//!    rather than tautological — it compares the CMap against the *font program*, a different
//!    source of truth.
//! 3. **`.notdef` is never shown.** A character absent from the face resolves to glyph 0; the
//!    writer would then record glyph 0 → that character, so the *next* missing character renders as
//!    the same blank box but extracts as the first one's text. Silent, wrong, and invisible to a
//!    presence check.
//! 4. **No lying or degenerate targets** — U+0000, U+FFFD and unpaired surrogates are rejected.
//! 5. **`/W` widths agree with `hmtx`**, and the CMap, the widths array and the shown glyphs
//!    describe the same glyph set (no stale entries, no gaps).
//!
//! The sfnt reader below is deliberately a second implementation rather than a call into
//! [`crate::font`]. A checker that resolves glyph ids with the same code the writer used to choose
//! them cannot detect a fault in that code.

use std::collections::{BTreeMap, BTreeSet};

/// Assert the composite font's `/ToUnicode`, `/W` and embedded program agree with each other and
/// with the glyphs the page content actually shows.
pub(super) fn verify(
    program: &[u8],
    length1: Option<i64>,
    to_unicode: &[u8],
    widths: &BTreeMap<u16, i64>,
    contents: &[(usize, Vec<u8>)],
) -> Result<(), String> {
    let sfnt = Sfnt::parse(program)?;
    if let Some(declared) = length1
        && declared != program.len() as i64
    {
        return Err(format!(
            "/FontFile2 /Length1 is {declared} but the embedded program is {} bytes",
            program.len()
        ));
    }

    let mut shown = BTreeSet::new();
    for (page_index, content) in contents {
        for gid in shown_glyph_ids(content).map_err(|e| format!("page {page_index}: {e}"))? {
            shown.insert(gid);
        }
    }
    if shown.is_empty() {
        return Err("no page shows any glyph — the document has no extractable text".into());
    }

    let mapping = parse_to_unicode(to_unicode)?;
    let cmap = sfnt.unicode_map()?;
    let num_glyphs = sfnt.num_glyphs()?;
    let units_per_em = sfnt.units_per_em()?;

    for &gid in &shown {
        if gid == 0 {
            return Err(
                "page content shows glyph 0 (.notdef): a character is missing from the embedded \
                 face, so it renders as a blank box and its /ToUnicode entry describes whichever \
                 character reached .notdef first"
                    .into(),
            );
        }
        if gid >= num_glyphs {
            return Err(format!(
                "page content shows glyph {gid} but the embedded program has only {num_glyphs} glyphs"
            ));
        }
        let scalars = mapping
            .get(&gid)
            .ok_or_else(|| format!("glyph {gid} is shown but has no /ToUnicode entry"))?;
        verify_scalars(gid, scalars)?;

        // The round-trip: the embedded font's own cmap must agree that this scalar is this glyph.
        if scalars.len() == 1 {
            let scalar = scalars[0];
            match cmap.get(&scalar) {
                Some(&mapped) if mapped == gid => {}
                Some(&mapped) => {
                    return Err(format!(
                        "/ToUnicode maps glyph {gid} to U+{scalar:04X}, but the embedded font maps \
                         U+{scalar:04X} to glyph {mapped}"
                    ));
                }
                None => {
                    return Err(format!(
                        "/ToUnicode maps glyph {gid} to U+{scalar:04X}, which the embedded font's \
                         cmap does not contain"
                    ));
                }
            }
        }

        let width = widths
            .get(&gid)
            .ok_or_else(|| format!("glyph {gid} is shown but has no /W width entry"))?;
        let expected = (sfnt.advance(gid)? as f32 * 1000.0 / units_per_em as f32).round() as i64;
        if *width != expected {
            return Err(format!(
                "glyph {gid} declares /W width {width} but the embedded hmtx gives {expected}"
            ));
        }
    }

    for gid in mapping.keys() {
        if !shown.contains(gid) {
            return Err(format!(
                "/ToUnicode carries an entry for glyph {gid}, which no page shows"
            ));
        }
    }
    for gid in widths.keys() {
        if !shown.contains(gid) {
            return Err(format!(
                "/W carries a width for glyph {gid}, which no page shows"
            ));
        }
    }

    Ok(())
}

/// Reject `/ToUnicode` targets that cannot represent real text.
fn verify_scalars(gid: u16, scalars: &[u32]) -> Result<(), String> {
    if scalars.is_empty() {
        return Err(format!("glyph {gid} has an empty /ToUnicode target"));
    }
    for &scalar in scalars {
        if scalar == 0 {
            return Err(format!("glyph {gid} maps to U+0000"));
        }
        if scalar == 0xFFFD {
            return Err(format!(
                "glyph {gid} maps to U+FFFD (the replacement character is not extractable text)"
            ));
        }
        if char::from_u32(scalar).is_none() {
            return Err(format!(
                "glyph {gid} maps to U+{scalar:04X}, which is not a Unicode scalar value \
                 (unpaired surrogate?)"
            ));
        }
    }
    Ok(())
}

// --- /ToUnicode CMap ------------------------------------------------------------------------------

/// Parse the `beginbfchar`/`beginbfrange` sections of a `/ToUnicode` CMap into glyph → scalars.
///
/// The codespace range is asserted to be the two-byte `<0000> <FFFF>` that Identity-H requires; a
/// one-byte codespace would silently truncate every code.
fn parse_to_unicode(cmap: &[u8]) -> Result<BTreeMap<u16, Vec<u32>>, String> {
    let text = String::from_utf8_lossy(cmap);
    if !text.contains("begincodespacerange") {
        return Err("/ToUnicode CMap declares no codespace range".into());
    }
    let codespace = section(&text, "begincodespacerange", "endcodespacerange")
        .ok_or("/ToUnicode CMap has an unterminated codespace range")?;
    if codespace.split_whitespace().collect::<Vec<_>>() != ["<0000>", "<FFFF>"] {
        return Err(format!(
            "/ToUnicode codespace range is `{}`, not the two-byte <0000> <FFFF> Identity-H requires",
            codespace.split_whitespace().collect::<Vec<_>>().join(" ")
        ));
    }

    let mut mapping: BTreeMap<u16, Vec<u32>> = BTreeMap::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find("beginbfchar") {
        let body = &rest[start + "beginbfchar".len()..];
        let end = body
            .find("endbfchar")
            .ok_or("/ToUnicode CMap has an unterminated bfchar section")?;
        for entry in bracketed(&body[..end]) {
            let [code, target] = <[String; 2]>::try_from(entry.clone()).map_err(|_| {
                format!(
                    "/ToUnicode bfchar entry has {} operands, expected a code and a target",
                    entry.len()
                )
            })?;
            let gid = parse_code(&code)?;
            let scalars = parse_utf16be(&target)?;
            if mapping.insert(gid, scalars).is_some() {
                return Err(format!("/ToUnicode maps glyph {gid} more than once"));
            }
        }
        rest = &body[end..];
    }

    if text.contains("beginbfrange") {
        return Err(
            "/ToUnicode uses a bfrange section; the writer emits bfchar entries only, so a bfrange \
             means the CMap was not produced by this writer"
                .into(),
        );
    }
    if mapping.is_empty() {
        return Err("/ToUnicode CMap has no bfchar mappings".into());
    }
    Ok(mapping)
}

fn section<'a>(text: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = text.find(open)? + open.len();
    let end = text[start..].find(close)? + start;
    Some(&text[start..end])
}

/// Split a CMap body into per-line groups of `<…>` operands.
fn bracketed(body: &str) -> Vec<Vec<String>> {
    body.lines()
        .filter_map(|line| {
            let items: Vec<String> = line
                .split_whitespace()
                .filter(|token| token.starts_with('<') && token.ends_with('>'))
                .map(|token| token[1..token.len() - 1].to_string())
                .collect();
            (!items.is_empty()).then_some(items)
        })
        .collect()
}

/// A two-byte Identity-H character code (== the glyph id).
fn parse_code(hex: &str) -> Result<u16, String> {
    if hex.len() != 4 {
        return Err(format!(
            "/ToUnicode source code <{hex}> is not the 4 hex digits Identity-H requires"
        ));
    }
    u16::from_str_radix(hex, 16).map_err(|_| format!("/ToUnicode source code <{hex}> is not hex"))
}

/// Decode a big-endian UTF-16 `/ToUnicode` target into Unicode scalars.
fn parse_utf16be(hex: &str) -> Result<Vec<u32>, String> {
    if hex.is_empty() || !hex.len().is_multiple_of(4) {
        return Err(format!(
            "/ToUnicode target <{hex}> is not a whole number of UTF-16 code units"
        ));
    }
    let mut units = Vec::with_capacity(hex.len() / 4);
    for chunk in hex.as_bytes().chunks(4) {
        let text = std::str::from_utf8(chunk).map_err(|_| "non-ASCII in a /ToUnicode target")?;
        units.push(
            u16::from_str_radix(text, 16)
                .map_err(|_| format!("/ToUnicode target <{hex}> is not hex"))?,
        );
    }
    // `decode_utf16` surfaces unpaired surrogates as errors, which `verify_scalars` then rejects.
    Ok(char::decode_utf16(units.iter().copied())
        .map(|result| result.map(|c| c as u32).unwrap_or(0xD800))
        .collect())
}

// --- Glyphs actually shown ------------------------------------------------------------------------

/// Recover the glyph ids a content stream shows, by tracking hex-string operands of the
/// text-showing operators.
fn shown_glyph_ids(content: &[u8]) -> Result<BTreeSet<u16>, String> {
    let mut shown = BTreeSet::new();
    let mut pending: Vec<Vec<u8>> = Vec::new();
    let mut index = 0usize;

    while index < content.len() {
        let byte = content[index];
        match byte {
            b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ' | b'[' | b']' => index += 1,
            b'%' => {
                while index < content.len() && content[index] != b'\n' && content[index] != b'\r' {
                    index += 1;
                }
            }
            b'(' => {
                index = skip_literal_string(content, index)?;
                // A literal string operand of `Tj` under Identity-H would be raw two-byte codes;
                // the writer never emits one, and treating it as opaque here would let glyphs
                // escape the check, so refuse it outright.
                pending.push(Vec::new());
            }
            b'<' if content.get(index + 1) != Some(&b'<') => {
                let end = content[index + 1..]
                    .iter()
                    .position(|&b| b == b'>')
                    .ok_or("unterminated hex string")?;
                pending.push(content[index + 1..index + 1 + end].to_vec());
                index += 1 + end + 1;
            }
            b'<' => index += 2,
            b'>' => index += 2,
            b'/' | b'{' | b'}' => {
                index += 1;
                if byte == b'/' {
                    while index < content.len() && is_regular(content[index]) {
                        index += 1;
                    }
                }
            }
            _ => {
                let start = index;
                while index < content.len() && is_regular(content[index]) {
                    index += 1;
                }
                if index == start {
                    return Err(format!("unparseable byte {byte:#04x} at offset {start}"));
                }
                let token = &content[start..index];
                if matches!(token, b"Tj" | b"TJ" | b"'" | b"\"") {
                    for hex in pending.drain(..) {
                        for gid in decode_identity_h(&hex)? {
                            shown.insert(gid);
                        }
                    }
                } else if !matches!(token, b"true" | b"false" | b"null")
                    && !token.iter().all(|b| {
                        b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.' | b'e' | b'E')
                    })
                {
                    pending.clear();
                }
            }
        }
    }
    Ok(shown)
}

/// Split an Identity-H hex operand into two-byte glyph ids.
fn decode_identity_h(hex: &[u8]) -> Result<Vec<u16>, String> {
    if hex.is_empty() {
        return Err(
            "a text-showing operator has a non-hex operand, so its glyphs cannot be \
                    checked against /ToUnicode"
                .into(),
        );
    }
    if !hex.len().is_multiple_of(4) {
        return Err(format!(
            "a text-showing hex operand has {} digits, not a whole number of two-byte Identity-H codes",
            hex.len()
        ));
    }
    let mut gids = Vec::with_capacity(hex.len() / 4);
    for chunk in hex.chunks(4) {
        let text = std::str::from_utf8(chunk).map_err(|_| "non-ASCII in a text hex operand")?;
        gids.push(
            u16::from_str_radix(text, 16)
                .map_err(|_| format!("text hex operand <{text}> is not hex"))?,
        );
    }
    Ok(gids)
}

fn is_regular(byte: u8) -> bool {
    !matches!(
        byte,
        b'\0'
            | b'\t'
            | b'\n'
            | b'\x0c'
            | b'\r'
            | b' '
            | b'('
            | b')'
            | b'<'
            | b'>'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'/'
            | b'%'
    )
}

fn skip_literal_string(content: &[u8], from: usize) -> Result<usize, String> {
    let mut index = from + 1;
    let mut depth = 1usize;
    while index < content.len() {
        match content[index] {
            b'\\' => index += 1,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(index + 1);
                }
            }
            _ => {}
        }
        index += 1;
    }
    Err("unterminated literal string".into())
}

// --- A second, independent sfnt reader ------------------------------------------------------------

/// The embedded font program's table directory, read straight from the `/FontFile2` bytes.
struct Sfnt<'a> {
    data: &'a [u8],
    tables: BTreeMap<[u8; 4], (usize, usize)>,
}

/// Tables a `CIDFontType2` program must carry for the PDF to render and extract.
const REQUIRED_TABLES: [&[u8; 4]; 5] = [b"head", b"hhea", b"maxp", b"hmtx", b"cmap"];

fn be16(bytes: &[u8], at: usize) -> Result<u16, String> {
    bytes
        .get(at..at + 2)
        .map(|w| u16::from_be_bytes([w[0], w[1]]))
        .ok_or_else(|| format!("embedded font program truncated at offset {at}"))
}

fn be32(bytes: &[u8], at: usize) -> Result<u32, String> {
    bytes
        .get(at..at + 4)
        .map(|w| u32::from_be_bytes([w[0], w[1], w[2], w[3]]))
        .ok_or_else(|| format!("embedded font program truncated at offset {at}"))
}

impl<'a> Sfnt<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, String> {
        let version = be32(data, 0)?;
        if !matches!(version, 0x0001_0000 | 0x7472_7565) {
            return Err(format!(
                "embedded /FontFile2 has sfnt version {version:#010x}, not a TrueType outline font"
            ));
        }
        let num_tables = be16(data, 4)? as usize;
        if num_tables == 0 {
            return Err("embedded font program has an empty table directory".into());
        }
        let mut tables = BTreeMap::new();
        for index in 0..num_tables {
            let entry = 12 + index * 16;
            let tag = data
                .get(entry..entry + 4)
                .ok_or("embedded font table directory is truncated")?;
            let offset = be32(data, entry + 8)? as usize;
            let length = be32(data, entry + 12)? as usize;
            let end = offset
                .checked_add(length)
                .ok_or("embedded font table extent overflows")?;
            if end > data.len() {
                return Err(format!(
                    "embedded font table `{}` spans {offset}..{end}, past the {}-byte program",
                    String::from_utf8_lossy(tag),
                    data.len()
                ));
            }
            tables.insert([tag[0], tag[1], tag[2], tag[3]], (offset, length));
        }

        for required in REQUIRED_TABLES {
            if !tables.contains_key(required) {
                return Err(format!(
                    "embedded font program has no `{}` table",
                    String::from_utf8_lossy(required)
                ));
            }
        }
        if !(tables.contains_key(b"glyf") && tables.contains_key(b"loca")) {
            return Err("embedded font program has no `glyf`/`loca` outline tables".into());
        }

        Ok(Sfnt { data, tables })
    }

    fn table(&self, tag: &[u8; 4]) -> Result<(usize, usize), String> {
        self.tables.get(tag).copied().ok_or_else(|| {
            format!(
                "embedded font program has no `{}` table",
                String::from_utf8_lossy(tag)
            )
        })
    }

    fn num_glyphs(&self) -> Result<u16, String> {
        let (offset, _) = self.table(b"maxp")?;
        be16(self.data, offset + 4)
    }

    fn units_per_em(&self) -> Result<u16, String> {
        let (offset, _) = self.table(b"head")?;
        let units = be16(self.data, offset + 18)?;
        if units == 0 {
            return Err("embedded font program declares unitsPerEm 0".into());
        }
        Ok(units)
    }

    /// Advance width of `gid` in design units, per `hhea`/`hmtx`.
    fn advance(&self, gid: u16) -> Result<u16, String> {
        let (hhea, _) = self.table(b"hhea")?;
        let num_metrics = be16(self.data, hhea + 34)? as usize;
        if num_metrics == 0 {
            return Err("embedded font program declares numberOfHMetrics 0".into());
        }
        let (hmtx, _) = self.table(b"hmtx")?;
        let index = (gid as usize).min(num_metrics - 1);
        be16(self.data, hmtx + index * 4)
    }

    /// Enumerate the font's Unicode `cmap` into a scalar → glyph map.
    ///
    /// Enumeration (rather than the point query [`crate::font`] uses) is what lets the caller
    /// detect a `/ToUnicode` entry whose scalar the font maps to a *different* glyph.
    fn unicode_map(&self) -> Result<BTreeMap<u32, u16>, String> {
        let (cmap, _) = self.table(b"cmap")?;
        let count = be16(self.data, cmap + 2)? as usize;
        let mut best: Option<usize> = None;
        let mut fallback: Option<usize> = None;
        for index in 0..count {
            let record = cmap + 4 + index * 8;
            let platform = be16(self.data, record)?;
            let encoding = be16(self.data, record + 2)?;
            let subtable = cmap + be32(self.data, record + 4)? as usize;
            if be16(self.data, subtable)? != 4 {
                continue;
            }
            if platform == 3 && encoding == 1 {
                best = Some(subtable);
            } else if platform == 0 {
                fallback = Some(subtable);
            }
        }
        let subtable = best
            .or(fallback)
            .ok_or("embedded font program has no format-4 Unicode cmap subtable")?;

        let seg_x2 = be16(self.data, subtable + 6)? as usize;
        if seg_x2 == 0 || !seg_x2.is_multiple_of(2) {
            return Err("embedded cmap format-4 has an invalid segCountX2".into());
        }
        let seg_count = seg_x2 / 2;
        let end_codes = subtable + 14;
        let start_codes = end_codes + seg_x2 + 2;
        let deltas = start_codes + seg_x2;
        let range_offsets = deltas + seg_x2;

        let mut map = BTreeMap::new();
        for segment in 0..seg_count {
            let end = be16(self.data, end_codes + segment * 2)?;
            let start = be16(self.data, start_codes + segment * 2)?;
            let delta = be16(self.data, deltas + segment * 2)? as i32;
            let range_offset = be16(self.data, range_offsets + segment * 2)? as usize;
            if start > end {
                return Err("embedded cmap format-4 has a reversed segment".into());
            }
            for code in start..=end {
                if code == 0xFFFF {
                    continue;
                }
                let gid = if range_offset == 0 {
                    ((code as i32 + delta) & 0xFFFF) as u16
                } else {
                    let address =
                        range_offsets + segment * 2 + range_offset + 2 * (code - start) as usize;
                    let raw = be16(self.data, address)?;
                    if raw == 0 {
                        continue;
                    }
                    ((raw as i32 + delta) & 0xFFFF) as u16
                };
                if gid != 0 {
                    map.insert(code as u32, gid);
                }
            }
        }
        Ok(map)
    }
}
