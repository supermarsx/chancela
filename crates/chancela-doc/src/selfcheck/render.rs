//! Colour-space and transparency rules, enforced as a **closed** operator and resource whitelist.
//!
//! The ISO 19005-2 colour and transparency corpus is large because it must describe every
//! construct a PDF can contain: Separation and DeviceN alternate spaces, Indexed base spaces,
//! ICCBased `/N` agreement, shading patterns, soft masks, transparency groups, non-`Normal` blend
//! modes. Enumerating checks for all of them would be a re-implementation of veraPDF.
//!
//! This module takes the other route the task admits: it proves the constructs **cannot be
//! present**. A PDF can only reference a colour space, an ExtGState, a shading, a pattern or an
//! XObject through the page's `/Resources`, or inline (`BI … ID … EI`). So a page whose
//! `/Resources` contains nothing but `/Font`, and whose content stream uses only operators drawn
//! from a closed list, is *incapable* of carrying any of them — no Separation, no DeviceN, no
//! Indexed, no shading, no pattern, no soft mask, no transparency group, no blend mode, no inline
//! image. That is a stronger statement than a post-hoc scan for each construct, and it stays true
//! for constructs nobody has thought of yet.
//!
//! Two rules here are genuine ISO rules rather than writer invariants, and are kept as such:
//! `k`/`K` (DeviceCMYK) is rejected because the file's only output intent is RGB, and `/Group` on
//! a page is rejected because a transparency group needs a declared blending colour space.

use lopdf::{Dictionary, Document, Object};

/// Every content-stream operator the writer is permitted to emit.
///
/// Deliberately narrow: text placement and showing, a black stroke/fill colour, thin-line path
/// painting for rules, and marked-content bracketing. Adding an operator here is a decision to
/// widen the writer's colour/transparency surface and must be made deliberately.
const ALLOWED_OPERATORS: &[&str] = &[
    // Graphics state (no `gs` — that is the ExtGState/transparency door).
    "q", "Q", "cm", "w", "M", "j", "J", "d", // Path construction and painting.
    "m", "l", "c", "v", "y", "h", "re", "S", "s", "f", "F", "f*", "B", "B*", "b", "b*", "n", "W",
    "W*", // Device colour only. `k`/`K` (DeviceCMYK) and `cs`/`CS`/`sc`/`scn`/`SC`/`SCN`
    // (named colour spaces) are absent by design.
    "g", "G", "rg", "RG", // Text.
    "BT", "ET", "Tf", "Td", "TD", "Tm", "T*", "TL", "Tc", "Tw", "Tz", "Ts", "Tr", "Tj", "TJ", "'",
    "\"", // Marked content.
    "BMC", "BDC", "EMC", "MP", "DP",
];

/// Resource categories a page may declare. Anything else is a construct we do not emit.
const ALLOWED_RESOURCE_KEYS: &[&[u8]] = &[b"Font", b"ProcSet"];

/// Assert every page carries only font resources, no transparency group, and a content stream
/// whose operators all come from [`ALLOWED_OPERATORS`].
pub(super) fn verify_pages(doc: &Document, contents: &[(usize, Vec<u8>)]) -> Result<(), String> {
    for (page_index, page_id) in doc.page_iter().enumerate() {
        let page = doc
            .get_object(page_id)
            .and_then(Object::as_dict)
            .map_err(|_| format!("page {page_index} object missing"))?;
        if page.has(b"Group") {
            return Err(format!(
                "page {page_index} declares a /Group transparency group"
            ));
        }
        let resources = page
            .get(b"Resources")
            .and_then(Object::as_dict)
            .map_err(|_| format!("page {page_index} has no /Resources dictionary"))?;
        verify_resources(resources, &format!("page {page_index}"))?;
    }

    for (page_index, content) in contents {
        verify_operators(content, &format!("page {page_index}"))?;
    }
    Ok(())
}

/// Assert a `/Resources` dictionary declares nothing but fonts.
pub(super) fn verify_resources(resources: &Dictionary, whose: &str) -> Result<(), String> {
    for (key, _) in resources.iter() {
        if !ALLOWED_RESOURCE_KEYS.contains(&key.as_slice()) {
            return Err(format!(
                "{whose} /Resources declares /{} — outside the writer's font-only resource profile \
                 (colour spaces, ExtGStates, shadings, patterns and XObjects are not emitted)",
                String::from_utf8_lossy(key)
            ));
        }
    }
    Ok(())
}

/// Assert every operator in `content` is on the whitelist.
pub(super) fn verify_operators(content: &[u8], whose: &str) -> Result<(), String> {
    for operator in operators(content)? {
        if !ALLOWED_OPERATORS.contains(&operator.as_str()) {
            let why = match operator.as_str() {
                "k" | "K" => " (DeviceCMYK, with no CMYK output intent)",
                "cs" | "CS" | "sc" | "SC" | "scn" | "SCN" => {
                    " (a named colour space: Separation, DeviceN, Indexed or Pattern)"
                }
                "gs" => " (an ExtGState: blend modes, soft masks, constant alpha)",
                "sh" => " (a shading, which may carry a pattern colour space)",
                "Do" => " (an external XObject: image or transparency-group form)",
                "BI" => " (an inline image, whose colour space bypasses /Resources)",
                _ => "",
            };
            return Err(format!(
                "{whose} content stream uses the operator `{operator}`{why}, which is outside the \
                 writer's closed operator profile"
            ));
        }
    }
    Ok(())
}

/// Tokenize a content stream and return its operators in order.
///
/// This is a real tokenizer rather than a line scan: operands are skipped by *type* (literal and
/// hex strings, names, numbers, arrays, dictionaries), so an operator cannot hide by sharing a line
/// with its operands or by sitting inside a string that happens to look like an operator.
fn operators(content: &[u8]) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    let mut index = 0usize;

    while index < content.len() {
        let byte = content[index];
        match byte {
            b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ' => index += 1,
            b'%' => {
                while index < content.len() && content[index] != b'\n' && content[index] != b'\r' {
                    index += 1;
                }
            }
            b'(' => index = skip_literal_string(content, index)?,
            b'<' => {
                if content.get(index + 1) == Some(&b'<') {
                    index += 2;
                } else {
                    index = skip_hex_string(content, index)?;
                }
            }
            b'>' => {
                if content.get(index + 1) == Some(&b'>') {
                    index += 2;
                } else {
                    return Err("content stream has a stray `>`".into());
                }
            }
            b'/' | b'[' | b']' | b'{' | b'}' => {
                index += 1;
                if byte == b'/' {
                    while index < content.len() && is_regular(content[index]) {
                        index += 1;
                    }
                }
            }
            b'+' | b'-' | b'.' | b'0'..=b'9' => {
                index += 1;
                while index < content.len() && is_regular(content[index]) {
                    index += 1;
                }
            }
            _ => {
                let start = index;
                while index < content.len() && is_regular(content[index]) {
                    index += 1;
                }
                if index == start {
                    return Err(format!(
                        "content stream has an unparseable byte {byte:#04x} at offset {start}"
                    ));
                }
                let token = String::from_utf8_lossy(&content[start..index]).into_owned();
                // `true`/`false`/`null` are operands, not operators.
                if !matches!(token.as_str(), "true" | "false" | "null") {
                    found.push(token);
                }
            }
        }
    }

    Ok(found)
}

/// A regular character: not whitespace and not one of the PDF delimiters.
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
    Err("content stream has an unterminated literal string".into())
}

fn skip_hex_string(content: &[u8], from: usize) -> Result<usize, String> {
    match content[from + 1..].iter().position(|&byte| byte == b'>') {
        Some(end) => Ok(from + 1 + end + 1),
        None => Err("content stream has an unterminated hex string".into()),
    }
}
