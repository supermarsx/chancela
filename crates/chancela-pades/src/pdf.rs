//! Low-level PDF byte utilities shared by signing and validation.
//!
//! These are deliberately hand-rolled (rather than driven through `lopdf`'s writer) so the exact
//! byte layout of the incremental update — and therefore the `/ByteRange` offsets — is fully under
//! our control. `lopdf` is used only to *parse* documents.

use lopdf::{Dictionary, Object, StringFormat};

/// Lowercase hex alphabet.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Encode bytes as lowercase ASCII hex.
pub(crate) fn to_hex(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
    out
}

/// Find the first occurrence of `needle` in `haystack`.
pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Find the last occurrence of `needle` in `haystack`.
pub(crate) fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// Read the byte offset named by the file's final `startxref` marker.
pub(crate) fn last_startxref(pdf: &[u8]) -> Option<usize> {
    let pos = rfind(pdf, b"startxref")?;
    let mut i = pos + b"startxref".len();
    while i < pdf.len() && matches!(pdf[i], b' ' | b'\r' | b'\n' | b'\t') {
        i += 1;
    }
    let start = i;
    while i < pdf.len() && pdf[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return None;
    }
    std::str::from_utf8(&pdf[start..i])
        .ok()?
        .parse::<usize>()
        .ok()
}

/// Compute the total encoded length (header + content) of the DER TLV at the start of `bytes`,
/// so a CMS object can be trimmed away from trailing `/Contents` zero-padding.
///
/// Handles definite-length DER with up to a 4-byte length (enough for any CMS we embed).
pub(crate) fn der_total_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 2 {
        return None;
    }
    let len_byte = bytes[1];
    if len_byte < 0x80 {
        // Short form.
        return Some(2 + len_byte as usize);
    }
    let n = (len_byte & 0x7f) as usize;
    if n == 0 || n > 4 || bytes.len() < 2 + n {
        return None;
    }
    let mut len = 0usize;
    for &b in &bytes[2..2 + n] {
        len = (len << 8) | b as usize;
    }
    Some(2 + n + len)
}

/// Append a PDF name (`/Foo`), `#`-escaping any byte that is not a regular character.
fn write_name(name: &[u8], out: &mut Vec<u8>) {
    out.push(b'/');
    for &b in name {
        let regular = b.is_ascii_graphic()
            && !matches!(
                b,
                b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%' | b'#'
            );
        if regular {
            out.push(b);
        } else {
            out.push(b'#');
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0x0f) as usize]);
        }
    }
}

/// Append a PDF string, literal `(...)` or hexadecimal `<...>`.
fn write_string(s: &[u8], fmt: StringFormat, out: &mut Vec<u8>) {
    match fmt {
        StringFormat::Hexadecimal => {
            out.push(b'<');
            out.extend_from_slice(&to_hex(s));
            out.push(b'>');
        }
        StringFormat::Literal => {
            out.push(b'(');
            for &b in s {
                match b {
                    b'(' | b')' | b'\\' => {
                        out.push(b'\\');
                        out.push(b);
                    }
                    _ => out.push(b),
                }
            }
            out.push(b')');
        }
    }
}

/// Serialize a single non-stream PDF object to bytes.
///
/// Returns `Err` for `Stream` objects: a stream cannot appear as a direct dictionary value in the
/// catalog / page objects we re-emit, and re-serializing arbitrary streams is out of scope.
pub(crate) fn write_object(obj: &Object, out: &mut Vec<u8>) -> Result<(), &'static str> {
    match obj {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Object::Integer(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Object::Real(r) => out.extend_from_slice(format!("{r}").as_bytes()),
        Object::Name(n) => write_name(n, out),
        Object::String(s, fmt) => write_string(s, *fmt, out),
        Object::Reference((num, generation)) => {
            out.extend_from_slice(format!("{num} {generation} R").as_bytes())
        }
        Object::Array(a) => {
            out.push(b'[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                write_object(e, out)?;
            }
            out.push(b']');
        }
        Object::Dictionary(d) => write_dict(d, out)?,
        Object::Stream(_) => return Err("stream object cannot be re-serialized here"),
    }
    Ok(())
}

/// Serialize a PDF dictionary (`<< ... >>`).
pub(crate) fn write_dict(dict: &Dictionary, out: &mut Vec<u8>) -> Result<(), &'static str> {
    out.extend_from_slice(b"<<");
    for (k, v) in dict.iter() {
        out.push(b' ');
        write_name(k, out);
        out.push(b' ');
        write_object(v, out)?;
    }
    out.extend_from_slice(b" >>");
    Ok(())
}

#[cfg(test)]
mod pdf_tests {
    use super::*;

    #[test]
    fn hex_roundtrip_shape() {
        assert_eq!(to_hex(&[0x00, 0xff, 0x10]), b"00ff10");
    }

    #[test]
    fn der_len_short_and_long_form() {
        // SEQUENCE, length 3 (short form): total 5.
        assert_eq!(der_total_len(&[0x30, 0x03, 0x01, 0x02, 0x03]), Some(5));
        // SEQUENCE, length 0x0130 = 304 (long form, 2 length octets): total 4 + 304.
        assert_eq!(der_total_len(&[0x30, 0x82, 0x01, 0x30]), Some(4 + 304));
    }

    #[test]
    fn last_startxref_reads_trailing_offset() {
        let pdf = b"%PDF-1.7\nstuff\nstartxref\n12345\n%%EOF\n";
        assert_eq!(last_startxref(pdf), Some(12345));
    }

    #[test]
    fn write_dict_emits_entries() {
        let mut d = Dictionary::new();
        d.set("Type", Object::Name(b"Catalog".to_vec()));
        d.set("Pages", Object::Reference((2, 0)));
        let mut out = Vec::new();
        write_dict(&d, &mut out).unwrap();
        assert_eq!(out, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
    }
}
