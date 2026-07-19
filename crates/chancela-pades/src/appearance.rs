//! Visible signature-seal appearance (`/AP /N`) building for PAdES signing.
//!
//! A PAdES signature widget carries an optional *normal appearance* stream (`/AP /N`) — a PDF form
//! XObject drawn inside the widget's `/Rect`. This module builds that appearance for the two seal
//! kinds the sign path offers:
//!
//! - **Text templates** ([`TextSeal`]) — a bordered box of one or more text lines (name + date
//!   variants and friends), drawn with the **font programme the document already embeds**, as a
//!   composite `Type0` / `Identity-H` font with its own `/ToUnicode` CMap and `/W` widths. See
//!   [`SealFont`] for why the seal shares the document's `/FontFile2` rather than bundling a face
//!   of its own. The line-drawing operators mirror the deterministic text patterns of
//!   `chancela-doc`'s `layout.rs` (copied, not shared — no cross-crate dependency).
//! - **Raster images** ([`ImageSeal`]) — a scanned/PNG/JPEG seal. JPEG bytes are embedded verbatim
//!   as a `/DCTDecode` image XObject (no re-encode). PNG is decoded (via the `png` crate) to raw
//!   8-bit samples stored as a `/FlateDecode` image XObject (`DeviceRGB` or `DeviceGray`); an alpha
//!   channel, if present, becomes a separate `DeviceGray` `/SMask` image so transparency is
//!   preserved over whatever the seal is placed on (rather than flattened onto an assumed
//!   background).
//!
//! The produced objects are serialized bodies ready to append to the incremental-update section in
//! [`crate::sign`]; that module owns object-number allocation, the widget `/Rect`, and the `/AP`
//! wiring.

use std::collections::BTreeMap;

use lopdf::{Dictionary, Object, Stream};

use crate::error::PadesError;
use crate::pdf;
use crate::sfnt::Sfnt;

/// A visible signature seal: where it goes ([`SealPlacement`]) and what it shows ([`SealContent`]).
///
/// Passed to [`crate::sign_pdf_with_appearance`] / [`crate::prepare_signature_with_appearance`].
/// When no [`SealAppearance`] is supplied those paths fall back to the invisible, locked widget
/// (`/Rect [0 0 0 0]`, no `/AP`) that is the backward-compatible default.
#[derive(Debug, Clone)]
pub struct SealAppearance {
    /// Where on the page the seal rectangle sits.
    pub placement: SealPlacement,
    /// What the seal draws (a text template or a raster image).
    pub content: SealContent,
}

/// Placement of a visible seal — **the coordinate spec the web designer (e12) and the seal-options
/// API (e9) must build against verbatim.**
///
/// # Coordinate convention (fixed here; consumers must match it exactly)
///
/// - **`page`** — zero-based page index. `0` is the document's first page. It indexes the page
///   tree's `/Kids` in document order (the current signing path assumes a flat page tree, as the
///   PDFs Chancela produces are).
/// - **Units** — PDF user-space **points** (1 point = 1/72 inch).
/// - **Origin & axes** — PDF default user space: the origin is the **bottom-left** corner of the
///   page and **`y` increases upward** (`y`-up). This is *not* screen/canvas space, where `y`
///   typically grows downward; a canvas overlay must flip `y` (`y_pdf = page_height - y_canvas -
///   h`) before filling these fields.
/// - **`x`, `y`** — the **lower-left** corner of the seal rectangle in that space.
/// - **`w`, `h`** — width and height of the seal rectangle, in points. Both must be **> 0**.
/// - The widget `/Rect` written from this is `[x, y, x + w, y + h]`, and the appearance form's
///   `/BBox` is `[0 0 w h]` with an identity matrix, so one point of seal content equals one point
///   of page space (text sizes and image scale are in points directly).
///
/// # Rotated pages (`/Rotate`)
///
/// `x, y, w, h` are always in the page's **default (unrotated) user space** — the `/MediaBox`
/// coordinate system *before* any `/Rotate` is applied. This is the standard PDF annotation rule:
/// `/Rect` is in default user space and the viewer applies `/Rotate` for display, so the seal lands
/// at the correct spot on a rotated page. The appearance content is drawn along the unrotated axes;
/// this phase does **not** auto-counter-rotate seal content for `/Rotate 90|180|270` pages (a
/// future `/Matrix` enhancement). Consumers targeting rotated pages should account for orientation
/// themselves.
#[derive(Debug, Clone)]
pub struct SealPlacement {
    /// Zero-based page index (`0` = first page).
    pub page: usize,
    /// Lower-left `x` of the seal rectangle, in points, default user space (`x`-right).
    pub x: f32,
    /// Lower-left `y` of the seal rectangle, in points, default user space (`y`-up).
    pub y: f32,
    /// Seal width in points (> 0).
    pub w: f32,
    /// Seal height in points (> 0).
    pub h: f32,
}

/// What a visible seal draws: a predefined text template or a raster image.
#[derive(Debug, Clone)]
pub enum SealContent {
    /// A bordered box of Helvetica text lines (name + date and similar templates).
    Text(TextSeal),
    /// A raster image (PNG or JPEG).
    Image(ImageSeal),
}

/// A text seal: a stack of styled lines, optionally boxed by a thin border.
#[derive(Debug, Clone)]
pub struct TextSeal {
    /// Lines drawn top-to-bottom inside the box.
    pub lines: Vec<SealTextLine>,
    /// Whether to stroke a thin rectangle just inside the seal edge.
    pub border: bool,
}

impl TextSeal {
    /// Predefined template: a bold signer **name** over a smaller **date/detail** line, boxed.
    pub fn name_date(name: impl Into<String>, date: impl Into<String>) -> Self {
        TextSeal {
            lines: vec![
                SealTextLine {
                    text: name.into(),
                    size: 10.0,
                    bold: true,
                },
                SealTextLine {
                    text: date.into(),
                    size: 8.0,
                    bold: false,
                },
            ],
            border: true,
        }
    }

    /// Predefined template: a small **heading** (e.g. "Assinado por"), the bold signer **name**, and
    /// a **date** line, boxed.
    pub fn signed_by(
        heading: impl Into<String>,
        name: impl Into<String>,
        date: impl Into<String>,
    ) -> Self {
        TextSeal {
            lines: vec![
                SealTextLine {
                    text: heading.into(),
                    size: 7.0,
                    bold: false,
                },
                SealTextLine {
                    text: name.into(),
                    size: 10.0,
                    bold: true,
                },
                SealTextLine {
                    text: date.into(),
                    size: 7.0,
                    bold: false,
                },
            ],
            border: true,
        }
    }
}

/// One styled line of a [`TextSeal`].
#[derive(Debug, Clone)]
pub struct SealTextLine {
    /// The line text. Every character must exist in the document's embedded font programme;
    /// one that does not is a signing error rather than a blank box (see [`SealFont`]).
    pub text: String,
    /// Font size in points.
    pub size: f32,
    /// Whether to emphasise the line. The document embeds one face, so emphasis is synthesised by
    /// stroking the glyph outlines as well as filling them (text rendering mode 2) rather than by
    /// switching to a bold face that is not there.
    pub bold: bool,
}

/// A raster-image seal: the encoded bytes plus their format.
#[derive(Debug, Clone)]
pub struct ImageSeal {
    /// The encoded image bytes (a full PNG or JPEG file).
    pub data: Vec<u8>,
    /// Which decoder path to use.
    pub format: SealImageFormat,
}

/// Supported raster seal formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealImageFormat {
    /// PNG — decoded to raw samples and stored `/FlateDecode` (alpha → `/SMask`).
    Png,
    /// JPEG — embedded verbatim as `/DCTDecode` (no re-encode).
    Jpeg,
}

/// The serialized appearance objects for one seal, ready to append to the incremental section.
pub(crate) struct BuiltAppearance {
    /// Object number of the `/AP /N` form XObject (what the widget's `/AP << /N … >>` references).
    pub normal_ap_num: u32,
    /// `(object number, serialized object body)` for every appearance object (form XObject, and for
    /// image seals the image XObject and optional `/SMask`). Bodies are the bytes between
    /// `"<n> 0 obj\n"` and `"\nendobj\n"`.
    pub objects: Vec<(u32, Vec<u8>)>,
}

/// The document's own embedded font programme, borrowed for the duration of one seal build.
///
/// A visible seal's `/AP /N` stream is the one place a signed file can acquire a font that never
/// passed through the document writer, and PDF/A-2 §6.2.11 requires every font used for rendering
/// to be embedded and (for the "u" conformance level) to carry a `/ToUnicode` CMap. Drawing seals
/// with a standard-14 face — as this module used to — silently made every visibly-sealed file
/// non-conformant.
///
/// The fix is not to bundle a font in this crate. That would add a whole font programme to every
/// signed file and would still be a *different* face from the one the document body uses. Instead
/// the seal reuses what is already in the input PDF: the seal's `/FontDescriptor` is the document's
/// descriptor, so the seal and the body share one `/FontFile2` stream and the signature adds no
/// font bytes at all. Only the small per-seal objects — the descendant `CIDFont` (with `/W` for the
/// seal's glyphs) and its `/ToUnicode` CMap — are new.
pub(crate) struct SealFont<'a> {
    /// The document's `/FontFile2` programme, parsed for `cmap` and `hmtx` lookups.
    pub(crate) program: Sfnt<'a>,
    /// Object id of the document's `/FontDescriptor`, referenced rather than rebuilt.
    pub(crate) descriptor: (u32, u16),
    /// The `/BaseFont` name the document uses, kept so the seal font names the same face.
    pub(crate) base_font: Vec<u8>,
}

/// Build the appearance objects for `content` in a `w`×`h` (points) box, allocating object numbers
/// starting at `first_num`. The `/AP /N` form XObject is always `first_num`; text seals also use
/// `first_num + 1..=first_num + 3` (`/ToUnicode`, descendant `CIDFont`, `Type0`), and image seals
/// `first_num + 1` (image) and, when the image has alpha, `first_num + 2` (`/SMask`).
pub(crate) fn build_appearance(
    content: &SealContent,
    w: f32,
    h: f32,
    first_num: u32,
    font: Option<&SealFont<'_>>,
) -> Result<BuiltAppearance, PadesError> {
    match content {
        SealContent::Text(seal) => {
            let font = font.ok_or_else(|| {
                PadesError::MalformedStructure(
                    "a text seal needs the document's embedded font programme".into(),
                )
            })?;
            build_text_appearance(seal, w, h, first_num, font)
        }
        SealContent::Image(seal) => build_image_appearance(seal, w, h, first_num),
    }
}

// --- Text seals ----------------------------------------------------------------------------------

fn build_text_appearance(
    seal: &TextSeal,
    w: f32,
    h: f32,
    first_num: u32,
    font: &SealFont<'_>,
) -> Result<BuiltAppearance, PadesError> {
    let ap_num = first_num;
    let to_unicode_num = first_num + 1;
    let cid_num = first_num + 2;
    let type0_num = first_num + 3;

    // `used` is glyph id → Unicode scalar, which is exactly what /ToUnicode and /W both need. It is
    // filled while the content stream is built, so the two describe the same glyph set by
    // construction: no stale entries, no gaps.
    let mut used: BTreeMap<u16, u32> = BTreeMap::new();
    let content = text_content_stream(seal, w, h, font, &mut used)?;
    if used.is_empty() {
        return Err(PadesError::MalformedStructure(
            "the text seal draws no characters, so the widget would show an empty box".into(),
        ));
    }

    let mut fonts = Dictionary::new();
    fonts.set("F1", Object::Reference((type0_num, 0)));
    let mut resources = Dictionary::new();
    resources.set("Font", Object::Dictionary(fonts));

    // Descendant CIDFont: Identity-H means CID == glyph id, so /W is keyed by glyph id directly and
    // /CIDToGIDMap is the identity. Widths come from the embedded `hmtx`, which is what a checker
    // compares them against.
    let mut widths = Vec::with_capacity(used.len() * 2);
    for &gid in used.keys() {
        widths.push(Object::Integer(gid as i64));
        widths.push(Object::Array(vec![Object::Integer(
            font.program.width_1000(gid)?,
        )]));
    }
    let mut cid = Dictionary::new();
    cid.set("Type", Object::Name(b"Font".to_vec()));
    cid.set("Subtype", Object::Name(b"CIDFontType2".to_vec()));
    cid.set("BaseFont", Object::Name(font.base_font.clone()));
    let mut system_info = Dictionary::new();
    system_info.set(
        "Registry",
        Object::String(b"Adobe".to_vec(), lopdf::StringFormat::Literal),
    );
    system_info.set(
        "Ordering",
        Object::String(b"Identity".to_vec(), lopdf::StringFormat::Literal),
    );
    system_info.set("Supplement", Object::Integer(0));
    cid.set("CIDSystemInfo", Object::Dictionary(system_info));
    cid.set("FontDescriptor", Object::Reference(font.descriptor));
    cid.set("CIDToGIDMap", Object::Name(b"Identity".to_vec()));
    cid.set("DW", Object::Integer(500));
    cid.set("W", Object::Array(widths));

    let mut type0 = Dictionary::new();
    type0.set("Type", Object::Name(b"Font".to_vec()));
    type0.set("Subtype", Object::Name(b"Type0".to_vec()));
    type0.set("BaseFont", Object::Name(font.base_font.clone()));
    type0.set("Encoding", Object::Name(b"Identity-H".to_vec()));
    type0.set(
        "DescendantFonts",
        Object::Array(vec![Object::Reference((cid_num, 0))]),
    );
    type0.set("ToUnicode", Object::Reference((to_unicode_num, 0)));

    let to_unicode = to_unicode_cmap(&used);
    let mut to_unicode_dict = Dictionary::new();
    to_unicode_dict.set("Length", Object::Integer(to_unicode.len() as i64));

    let dict_body = |dict: &Dictionary| -> Result<Vec<u8>, PadesError> {
        let mut out = Vec::new();
        pdf::write_dict(dict, &mut out).map_err(|m| PadesError::MalformedStructure(m.into()))?;
        Ok(out)
    };

    Ok(BuiltAppearance {
        normal_ap_num: ap_num,
        objects: vec![
            (ap_num, form_xobject_body(w, h, resources, content)?),
            (
                to_unicode_num,
                stream_object_body(&to_unicode_dict, &to_unicode)?,
            ),
            (cid_num, dict_body(&cid)?),
            (type0_num, dict_body(&type0)?),
        ],
    })
}

/// Build the content stream: an optional border rectangle, then each line placed top-to-bottom,
/// recording every glyph shown in `used`.
fn text_content_stream(
    seal: &TextSeal,
    w: f32,
    h: f32,
    font: &SealFont<'_>,
    used: &mut BTreeMap<u16, u32>,
) -> Result<Vec<u8>, PadesError> {
    let mut s: Vec<u8> = Vec::new();
    if seal.border {
        // Thin black rectangle inset 0.5pt from the box edge.
        s.extend_from_slice(
            format!(
                "q\n0 0 0 RG\n0.75 w\n{} {} {} {} re\nS\nQ\n",
                num(0.5),
                num(0.5),
                num((w - 1.0).max(0.0)),
                num((h - 1.0).max(0.0)),
            )
            .as_bytes(),
        );
    }
    let inset = 4.0f32;
    let mut baseline = h - inset;
    for line in &seal.lines {
        baseline -= line.size;
        if baseline < inset {
            break; // out of vertical room; drop remaining lines rather than overflow the box
        }
        let glyphs = shape(&line.text, font, used)?;
        if glyphs.is_empty() {
            baseline -= line.size * 0.35;
            continue;
        }
        s.extend_from_slice(b"BT\n");
        s.extend_from_slice(format!("/F1 {} Tf\n", num(line.size)).as_bytes());
        s.extend_from_slice(b"0 g\n");
        if line.bold {
            // Synthetic emphasis: fill *and* stroke the outlines (mode 2). The document embeds one
            // face, and inventing a bold one is not something a signer may do.
            s.extend_from_slice(b"0 0 0 RG\n2 Tr\n");
            s.extend_from_slice(format!("{} w\n", num(line.size * 0.03)).as_bytes());
        } else {
            s.extend_from_slice(b"0 Tr\n");
        }
        s.extend_from_slice(format!("{} {} Td\n", num(inset), num(baseline)).as_bytes());
        s.push(b'<');
        for gid in glyphs {
            s.extend_from_slice(format!("{gid:04X}").as_bytes());
        }
        s.extend_from_slice(b"> Tj\nET\n");
        baseline -= line.size * 0.35; // inter-line gap
    }
    Ok(s)
}

/// Resolve `text` to glyph ids through the embedded font's `cmap`, recording each in `used`.
///
/// A character the face does not have resolves to glyph 0 (`.notdef`), which renders as a blank box
/// and whose `/ToUnicode` entry would describe whichever character reached `.notdef` first — silent,
/// wrong, and undetectable by a check that only asks whether a CMap exists. So it is refused.
fn shape(
    text: &str,
    font: &SealFont<'_>,
    used: &mut BTreeMap<u16, u32>,
) -> Result<Vec<u16>, PadesError> {
    let mut glyphs = Vec::with_capacity(text.len());
    for ch in text.chars() {
        // Line breaks have no glyph and no meaning inside a single seal line.
        if ch == '\n' || ch == '\r' {
            continue;
        }
        let gid = font.program.glyph_id(ch)?;
        if gid == 0 {
            return Err(PadesError::MalformedStructure(format!(
                "seal text contains {ch:?} (U+{:04X}), which the document's embedded font \
                 programme has no glyph for — drawing it would show a blank box and corrupt the \
                 seal's extractable text",
                ch as u32
            )));
        }
        // First scalar wins, deterministically: two characters sharing a glyph (a no-break space
        // and a space, say) would both round-trip, and picking one keeps the CMap single-valued.
        used.entry(gid).or_insert(ch as u32);
        glyphs.push(gid);
    }
    Ok(glyphs)
}

/// Build the `/ToUnicode` CMap for the seal's glyphs, in the `bfchar` form a checker can compare
/// against the embedded font's own `cmap`.
fn to_unicode_cmap(used: &BTreeMap<u16, u32>) -> Vec<u8> {
    let mut body = String::from(
        "/CIDInit /ProcSet findresource begin\n\
12 dict begin\n\
begincmap\n\
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n\
/CMapName /Adobe-Identity-UCS def\n\
/CMapType 2 def\n\
1 begincodespacerange\n\
<0000> <FFFF>\n\
endcodespacerange\n",
    );
    let entries: Vec<(u16, u32)> = used.iter().map(|(&gid, &scalar)| (gid, scalar)).collect();
    for chunk in entries.chunks(100) {
        body.push_str(&format!("{} beginbfchar\n", chunk.len()));
        for &(gid, scalar) in chunk {
            body.push_str(&format!("<{gid:04X}> <{}>\n", utf16be_hex(scalar)));
        }
        body.push_str("endbfchar\n");
    }
    body.push_str(
        "endcmap\n\
CMapName currentdict /CMap defineresource pop\n\
end\n\
end",
    );
    body.into_bytes()
}

/// Encode a Unicode scalar as big-endian UTF-16 hex (a surrogate pair outside the BMP).
fn utf16be_hex(scalar: u32) -> String {
    match char::from_u32(scalar) {
        Some(c) => {
            let mut buf = [0u16; 2];
            c.encode_utf16(&mut buf)
                .iter()
                .map(|unit| format!("{unit:04X}"))
                .collect()
        }
        None => "FFFD".to_string(),
    }
}

// --- Image seals ---------------------------------------------------------------------------------

/// A decoded raster ready to embed: interleaved 8-bit color samples, optional 8-bit alpha, and the
/// PDF color space. For JPEG the "samples" are the untouched JPEG file bytes and `jpeg` is set.
struct DecodedImage {
    width: u32,
    height: u32,
    color_space: &'static str,
    samples: Vec<u8>,
    alpha: Option<Vec<u8>>,
    jpeg: bool,
}

fn build_image_appearance(
    seal: &ImageSeal,
    w: f32,
    h: f32,
    first_num: u32,
) -> Result<BuiltAppearance, PadesError> {
    let ap_num = first_num;
    let img_num = first_num + 1;
    let decoded = decode_image(seal)?;
    let smask_num = decoded.alpha.as_ref().map(|_| first_num + 2);

    let mut objects: Vec<(u32, Vec<u8>)> = Vec::new();

    // Image XObject.
    let mut img_dict = Dictionary::new();
    img_dict.set("Type", Object::Name(b"XObject".to_vec()));
    img_dict.set("Subtype", Object::Name(b"Image".to_vec()));
    img_dict.set("Width", Object::Integer(decoded.width as i64));
    img_dict.set("Height", Object::Integer(decoded.height as i64));
    img_dict.set(
        "ColorSpace",
        Object::Name(decoded.color_space.as_bytes().to_vec()),
    );
    img_dict.set("BitsPerComponent", Object::Integer(8));
    if let Some(sm) = smask_num {
        img_dict.set("SMask", Object::Reference((sm, 0)));
    }
    objects.push((
        img_num,
        image_object_body(img_dict, decoded.samples, decoded.jpeg)?,
    ));

    // Alpha soft-mask image (always FlateDecode DeviceGray).
    if let (Some(sm), Some(alpha)) = (smask_num, decoded.alpha) {
        let mut sm_dict = Dictionary::new();
        sm_dict.set("Type", Object::Name(b"XObject".to_vec()));
        sm_dict.set("Subtype", Object::Name(b"Image".to_vec()));
        sm_dict.set("Width", Object::Integer(decoded.width as i64));
        sm_dict.set("Height", Object::Integer(decoded.height as i64));
        sm_dict.set("ColorSpace", Object::Name(b"DeviceGray".to_vec()));
        sm_dict.set("BitsPerComponent", Object::Integer(8));
        objects.push((sm, image_object_body(sm_dict, alpha, false)?));
    }

    // Form XObject that scales the unit-square image to fill the w×h box.
    let content = format!("q\n{} 0 0 {} 0 0 cm\n/Im0 Do\nQ\n", num(w), num(h)).into_bytes();
    let mut xobjects = Dictionary::new();
    xobjects.set("Im0", Object::Reference((img_num, 0)));
    let mut resources = Dictionary::new();
    resources.set("XObject", Object::Dictionary(xobjects));
    objects.push((ap_num, form_xobject_body(w, h, resources, content)?));

    Ok(BuiltAppearance {
        normal_ap_num: ap_num,
        objects,
    })
}

fn decode_image(seal: &ImageSeal) -> Result<DecodedImage, PadesError> {
    match seal.format {
        SealImageFormat::Jpeg => decode_jpeg(&seal.data),
        SealImageFormat::Png => decode_png(&seal.data),
    }
}

/// Decode a PNG to 8-bit samples (palette/low-bit-depth expanded, 16-bit stripped to 8), splitting
/// any alpha channel out into `alpha` for a `/SMask`.
fn decode_png(data: &[u8]) -> Result<DecodedImage, PadesError> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(data));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder
        .read_info()
        .map_err(|e| PadesError::MalformedStructure(format!("PNG header: {e}")))?;
    let output_size = reader.output_buffer_size().ok_or_else(|| {
        PadesError::MalformedStructure("PNG dimensions overflow the output buffer size".to_owned())
    })?;
    let mut buf = vec![0u8; output_size];
    let info = reader
        .next_frame(&mut buf)
        .map_err(|e| PadesError::MalformedStructure(format!("PNG decode: {e}")))?;
    let pixels = &buf[..info.buffer_size()];
    let (width, height) = (info.width, info.height);
    let count = (width as usize).saturating_mul(height as usize);

    let decoded = match info.color_type {
        png::ColorType::Grayscale => DecodedImage {
            width,
            height,
            color_space: "DeviceGray",
            samples: pixels.to_vec(),
            alpha: None,
            jpeg: false,
        },
        png::ColorType::Rgb => DecodedImage {
            width,
            height,
            color_space: "DeviceRGB",
            samples: pixels.to_vec(),
            alpha: None,
            jpeg: false,
        },
        png::ColorType::GrayscaleAlpha => {
            let mut samples = Vec::with_capacity(count);
            let mut alpha = Vec::with_capacity(count);
            for px in pixels.chunks_exact(2) {
                samples.push(px[0]);
                alpha.push(px[1]);
            }
            DecodedImage {
                width,
                height,
                color_space: "DeviceGray",
                samples,
                alpha: Some(alpha),
                jpeg: false,
            }
        }
        png::ColorType::Rgba => {
            let mut samples = Vec::with_capacity(count * 3);
            let mut alpha = Vec::with_capacity(count);
            for px in pixels.chunks_exact(4) {
                samples.extend_from_slice(&px[..3]);
                alpha.push(px[3]);
            }
            DecodedImage {
                width,
                height,
                color_space: "DeviceRGB",
                samples,
                alpha: Some(alpha),
                jpeg: false,
            }
        }
        other => {
            return Err(PadesError::MalformedStructure(format!(
                "unsupported PNG color type after expansion: {other:?}"
            )));
        }
    };
    Ok(decoded)
}

/// "Decode" a JPEG by locating its Start-Of-Frame marker to read the dimensions and component
/// count; the pixel data is embedded verbatim as `/DCTDecode`.
fn decode_jpeg(data: &[u8]) -> Result<DecodedImage, PadesError> {
    let (width, height, components) = jpeg_frame_header(data)?;
    let color_space = match components {
        1 => "DeviceGray",
        3 => "DeviceRGB",
        4 => "DeviceCMYK",
        n => {
            return Err(PadesError::MalformedStructure(format!(
                "unsupported JPEG component count: {n}"
            )));
        }
    };
    Ok(DecodedImage {
        width,
        height,
        color_space,
        samples: data.to_vec(),
        alpha: None,
        jpeg: true,
    })
}

/// Scan JPEG markers for the first Start-Of-Frame (SOF0–SOF15, excluding DHT/JPG/DAC) and return
/// `(width, height, components)`.
fn jpeg_frame_header(data: &[u8]) -> Result<(u32, u32, u8), PadesError> {
    let malformed =
        || PadesError::MalformedStructure("not a JPEG or no Start-Of-Frame marker".to_string());
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return Err(malformed());
    }
    let mut i = 2usize;
    while i + 1 < data.len() {
        if data[i] != 0xFF {
            i += 1;
            continue;
        }
        // Collapse any fill 0xFF bytes preceding the marker.
        let mut m = i + 1;
        while m < data.len() && data[m] == 0xFF {
            m += 1;
        }
        if m >= data.len() {
            break;
        }
        let marker = data[m];
        i = m + 1;
        // Standalone markers carry no length: SOI, EOI, RSTn, TEM.
        if marker == 0xD8 || marker == 0xD9 || (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
            continue;
        }
        if i + 2 > data.len() {
            break;
        }
        let len = ((data[i] as usize) << 8) | data[i + 1] as usize;
        if len < 2 {
            break;
        }
        let payload = i + 2;
        let is_sof = (0xC0..=0xCF).contains(&marker) && !matches!(marker, 0xC4 | 0xC8 | 0xCC);
        if is_sof {
            // SOF payload: precision(1) height(2) width(2) components(1) …
            if payload + 6 > data.len() {
                break;
            }
            let height = ((data[payload + 1] as u32) << 8) | data[payload + 2] as u32;
            let width = ((data[payload + 3] as u32) << 8) | data[payload + 4] as u32;
            let components = data[payload + 5];
            if width == 0 || height == 0 {
                return Err(malformed());
            }
            return Ok((width, height, components));
        }
        if marker == 0xDA {
            break; // Start-Of-Scan: compressed data follows, no header past here.
        }
        i += len;
    }
    Err(malformed())
}

// --- Shared serialization helpers ----------------------------------------------------------------

/// Serialize a form XObject (`/Subtype /Form`, `/BBox [0 0 w h]`, identity matrix) wrapping
/// `content`, with the given `/Resources`.
fn form_xobject_body(
    w: f32,
    h: f32,
    resources: Dictionary,
    content: Vec<u8>,
) -> Result<Vec<u8>, PadesError> {
    let mut dict = Dictionary::new();
    dict.set("Type", Object::Name(b"XObject".to_vec()));
    dict.set("Subtype", Object::Name(b"Form".to_vec()));
    dict.set("FormType", Object::Integer(1));
    dict.set(
        "BBox",
        Object::Array(vec![
            Object::Real(0.0),
            Object::Real(0.0),
            Object::Real(w),
            Object::Real(h),
        ]),
    );
    dict.set("Resources", Object::Dictionary(resources));
    let mut stream = Stream::new(dict, content);
    // Deflate the content stream when it pays off (Stream::compress no-ops on tiny streams).
    stream.compress().ok();
    stream_object_body(&stream.dict, &stream.content)
}

/// Serialize an image XObject body. JPEG bytes are stored verbatim under `/DCTDecode`; raw samples
/// are `/FlateDecode`-compressed (falling back to uncompressed when compression does not help).
fn image_object_body(
    mut dict: Dictionary,
    content: Vec<u8>,
    jpeg: bool,
) -> Result<Vec<u8>, PadesError> {
    if jpeg {
        dict.set("Filter", Object::Name(b"DCTDecode".to_vec()));
        dict.set("Length", Object::Integer(content.len() as i64));
        stream_object_body(&dict, &content)
    } else {
        let mut stream = Stream::new(dict, content);
        stream.compress().ok();
        stream_object_body(&stream.dict, &stream.content)
    }
}

/// Serialize a stream object body: `<< dict >>\nstream\n<content>\nendstream`. `dict` must already
/// carry the correct `/Length` (and `/Filter`), which the `lopdf::Stream` builders set.
fn stream_object_body(dict: &Dictionary, content: &[u8]) -> Result<Vec<u8>, PadesError> {
    let mut out = Vec::with_capacity(content.len() + 64);
    pdf::write_dict(dict, &mut out).map_err(|m| PadesError::MalformedStructure(m.to_string()))?;
    out.extend_from_slice(b"\nstream\n");
    out.extend_from_slice(content);
    out.extend_from_slice(b"\nendstream");
    Ok(out)
}

/// Format a coordinate deterministically (fixed 2 decimals, no negative zero) — copied from the
/// `chancela-doc` layout patterns for byte-stable output.
fn num(x: f32) -> String {
    let x = if x.abs() < 0.005 { 0.0 } else { x };
    format!("{x:.2}")
}
