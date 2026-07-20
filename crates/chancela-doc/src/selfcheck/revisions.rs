//! Cross-reference **chain** walking — the structure a signed file has and a freshly written one
//! does not.
//!
//! `pdfa::write` emits exactly one revision, so the write-time gate could get away with looking at
//! a single classic `xref` table. `chancela-pades` appends an incremental update after `write`
//! returns: the file then has *two or more* cross-reference sections chained by `/Prev`, and the
//! authoritative trailer is the **last** one. Anything that reasons about "the trailer" by taking
//! the first `trailer` keyword, or by trusting `lopdf`'s merged view, is reading the wrong bytes.
//!
//! Concretely, `lopdf` merges the chain and **drops** `/ID` when the newest trailer omits it — so
//! the ISO 19005-2 §6.1.3 `/ID` requirement cannot be checked through `Document::trailer` at all.
//! This module reads each revision's trailer from the raw bytes instead.
//!
//! The parser here is deliberately minimal: a trailer dictionary is a flat `<< … >>` of atoms, and
//! we only need `/Prev`, `/ID`, `/Root`, `/Encrypt` and `/XRefStm`. Writing ~100 lines rather than
//! reaching into `lopdf` internals also keeps the check *independent* of the parser whose output we
//! are trying to corroborate.

/// One cross-reference section and the trailer that follows it, located in the raw file bytes.
pub(super) struct Revision {
    /// Byte offset of this revision's `xref` keyword.
    pub xref_offset: usize,
    /// Raw bytes of this revision's trailer dictionary, `<<` … `>>` inclusive.
    pub trailer: Vec<u8>,
}

impl Revision {
    /// The `/ID` array's two hex strings, if the trailer carries a well-formed two-element `/ID`.
    pub fn id_pair(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let rest = after_key(&self.trailer, b"/ID")?;
        let rest = skip_ws(rest);
        let rest = rest.strip_prefix(b"[")?;
        let (first, rest) = hex_string(skip_ws(rest))?;
        let (second, _) = hex_string(skip_ws(rest))?;
        Some((first, second))
    }

    pub fn has_key(&self, key: &[u8]) -> bool {
        after_key(&self.trailer, key).is_some()
    }

    fn prev(&self) -> Option<usize> {
        integer(skip_ws(after_key(&self.trailer, b"/Prev")?))
    }
}

/// Walk the `/Prev` chain from the file's final `startxref`, newest revision first.
///
/// Every hop is asserted to land on a classic `xref` keyword, so a cross-reference **stream**
/// anywhere in the chain — not just at the end — is rejected. Cycles and runaway chains are bounded
/// rather than trusted.
pub(super) fn chain(bytes: &[u8]) -> Result<Vec<Revision>, String> {
    let mut offset = super::last_startxref(bytes)
        .ok_or_else(|| "file has no readable trailing `startxref` offset".to_string())?;
    let mut seen = Vec::new();
    let mut revisions = Vec::new();

    loop {
        if seen.contains(&offset) {
            return Err(format!(
                "cross-reference chain loops back to offset {offset}"
            ));
        }
        seen.push(offset);
        if revisions.len() > 64 {
            return Err("cross-reference chain is longer than 64 revisions".into());
        }

        if bytes.get(offset..offset + 4) != Some(b"xref") {
            return Err(format!(
                "cross-reference section at offset {offset} is not a classic `xref` table \
                 (cross-reference stream?)"
            ));
        }
        let trailer = trailer_after(bytes, offset).ok_or_else(|| {
            format!("cross-reference section at offset {offset} has no `trailer` dictionary")
        })?;
        let revision = Revision {
            xref_offset: offset,
            trailer,
        };
        let prev = revision.prev();
        revisions.push(revision);

        match prev {
            Some(previous) => offset = previous,
            None => break,
        }
    }

    Ok(revisions)
}

/// Extract the `<< … >>` following the `trailer` keyword that follows the xref table at `from`.
fn trailer_after(bytes: &[u8], from: usize) -> Option<Vec<u8>> {
    let region = bytes.get(from..)?;
    let keyword = super::find_slice(region, b"trailer")?;
    let mut index = from + keyword + b"trailer".len();
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if bytes.get(index..index + 2) != Some(b"<<") {
        return None;
    }

    // Balance `<<`/`>>`, skipping literal strings so a `>>` inside `(…)` cannot close the dict.
    let mut depth = 0usize;
    let mut cursor = index;
    while cursor + 1 < bytes.len() {
        match &bytes[cursor..cursor + 2] {
            b"<<" => {
                depth += 1;
                cursor += 2;
            }
            b">>" => {
                depth -= 1;
                cursor += 2;
                if depth == 0 {
                    return Some(bytes[index..cursor].to_vec());
                }
            }
            _ if bytes[cursor] == b'(' => {
                cursor += 1;
                let mut nesting = 1usize;
                while cursor < bytes.len() && nesting > 0 {
                    match bytes[cursor] {
                        b'\\' => cursor += 1,
                        b'(' => nesting += 1,
                        b')' => nesting -= 1,
                        _ => {}
                    }
                    cursor += 1;
                }
            }
            _ => cursor += 1,
        }
    }
    None
}

/// The bytes following `key` in `dict`, matching only on a whole name token.
fn after_key<'a>(dict: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut from = 0usize;
    while let Some(hit) = super::find_slice(&dict[from..], key) {
        let start = from + hit;
        let end = start + key.len();
        // `/ID` must not match the `/ID` prefix of `/IDSomething`.
        let delimited = dict
            .get(end)
            .is_none_or(|&byte| !byte.is_ascii_alphanumeric() && byte != b'.' && byte != b'-');
        if delimited {
            return Some(&dict[end..]);
        }
        from = end;
    }
    None
}

fn skip_ws(bytes: &[u8]) -> &[u8] {
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    &bytes[index..]
}

fn integer(bytes: &[u8]) -> Option<usize> {
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    std::str::from_utf8(&bytes[..index]).ok()?.parse().ok()
}

/// Parse `<hex…>` into its decoded bytes, returning the remainder.
fn hex_string(bytes: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let rest = bytes.strip_prefix(b"<")?;
    let end = rest.iter().position(|&byte| byte == b'>')?;
    let digits = &rest[..end];
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some((out, &rest[end + 1..]))
}
