//! Deterministic XMP metadata packet carrying the PDF/A-2u identification (`pdfaid:part=2`,
//! `pdfaid:conformance=U`) plus Dublin Core / XMP-basic properties.
//!
//! The packet is emitted as a plaintext UTF-8 stream with **no `/Filter`** (PDF/A forbids a
//! compressed metadata stream). Every value derives from the [`DocumentModel`] — no clock, no RNG —
//! so the same model yields byte-identical metadata. There is deliberately **no Info dictionary**:
//! metadata lives only here, side-stepping Info↔XMP consistency checks.

use chancela_core::DocumentModel;

/// The producer/creator tool string embedded in the metadata.
pub const CREATOR_TOOL: &str = "Chancela chancela-doc";

/// Escape the five XML predefined entities.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Normalise a caller-supplied `created_at` into an ISO-8601 timestamp with a zone designator.
///
/// Deterministic: a `Some` value is passed through (a bare `YYYY-MM-DD` is completed to midnight
/// UTC); `None` falls back to a fixed constant (never `now()`), keeping output reproducible.
pub fn iso_date(created_at: &Option<String>) -> String {
    match created_at {
        Some(s) if s.contains('T') => s.clone(),
        Some(s) if s.len() == 10 && s.as_bytes()[4] == b'-' => format!("{s}T00:00:00Z"),
        Some(s) if !s.is_empty() => s.clone(),
        _ => "1970-01-01T00:00:00Z".to_string(),
    }
}

/// Build the full XMP packet bytes for `doc`.
pub fn packet(doc: &DocumentModel) -> Vec<u8> {
    let date = iso_date(&doc.created_at);
    let title = xml_escape(&doc.title);
    let lang = xml_escape(&doc.language);
    let creator = xml_escape(&doc.entity_name);
    let date = xml_escape(&date);

    // NOTE: keep only predefined schemas (pdfaid, dc, xmp, pdf) so no pdfaExtension block is needed.
    let xml = format!(
        "<?xpacket begin=\"\u{feff}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n\
 <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n\
  <rdf:Description rdf:about=\"\"\n\
      xmlns:pdfaid=\"http://www.aiim.org/pdfa/ns/id/\"\n\
      xmlns:dc=\"http://purl.org/dc/elements/1.1/\"\n\
      xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"\n\
      xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\">\n\
   <pdfaid:part>2</pdfaid:part>\n\
   <pdfaid:conformance>U</pdfaid:conformance>\n\
   <dc:format>application/pdf</dc:format>\n\
   <dc:title>\n\
    <rdf:Alt>\n\
     <rdf:li xml:lang=\"x-default\">{title}</rdf:li>\n\
    </rdf:Alt>\n\
   </dc:title>\n\
   <dc:creator>\n\
    <rdf:Seq>\n\
     <rdf:li>{creator}</rdf:li>\n\
    </rdf:Seq>\n\
   </dc:creator>\n\
   <dc:language>\n\
    <rdf:Bag>\n\
     <rdf:li>{lang}</rdf:li>\n\
    </rdf:Bag>\n\
   </dc:language>\n\
   <xmp:CreateDate>{date}</xmp:CreateDate>\n\
   <xmp:ModifyDate>{date}</xmp:ModifyDate>\n\
   <xmp:MetadataDate>{date}</xmp:MetadataDate>\n\
   <xmp:CreatorTool>{tool}</xmp:CreatorTool>\n\
   <pdf:Producer>{tool}</pdf:Producer>\n\
  </rdf:Description>\n\
 </rdf:RDF>\n\
</x:xmpmeta>\n\
<?xpacket end=\"w\"?>",
        title = title,
        creator = creator,
        lang = lang,
        date = date,
        tool = CREATOR_TOOL,
    );
    xml.into_bytes()
}
