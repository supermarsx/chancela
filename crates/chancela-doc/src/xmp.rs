//! Deterministic XMP metadata packet carrying the PDF/A-2u identification (`pdfaid:part=2`,
//! `pdfaid:conformance=U`) plus Dublin Core / XMP-basic properties.
//!
//! When the document conforms to the writer's PDF/UA profile the packet **also** carries the
//! PDF/UA-1 identifier (`pdfuaid:part=1`) and the mandatory `pdfaExtension` schema description for
//! the `pdfuaid` namespace (a non-predefined schema used in a PDF/A file must be described by an
//! extension block, else veraPDF fails *both* PDF/A and PDF/UA). The UA identifier is emitted only
//! for conforming documents — a non-conforming model stays a plain, valid PDF/A-2U file with no UA
//! claim, so the claim is never false.
//!
//! The packet is emitted as a plaintext UTF-8 stream with **no `/Filter`** (PDF/A forbids a
//! compressed metadata stream). Every value derives from the [`DocumentModel`] — no clock, no RNG —
//! so the same model yields byte-identical metadata. There is deliberately **no Info dictionary**:
//! metadata lives only here, side-stepping Info↔XMP consistency checks.

use chancela_core::DocumentModel;

use crate::accessibility::AccessibilityMetadata;

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

/// The PDF/UA-1 identification namespace.
const PDFUAID_NS: &str = "http://www.aiim.org/pdfua/ns/id/";

/// The `pdfaExtension` schema description for the `pdfuaid` namespace. Mandatory in a PDF/A file
/// that uses any schema outside the predefined set; a malformed block fails veraPDF PDF/A **and**
/// PDF/UA, so the prefix/namespace/valueType are exact per ISO 14289-1 / veraPDF expectations.
const PDFUA_EXTENSION_SCHEMA: &str = "\
  <rdf:Description rdf:about=\"\"\n\
      xmlns:pdfaExtension=\"http://www.aiim.org/pdfa/ns/extension/\"\n\
      xmlns:pdfaSchema=\"http://www.aiim.org/pdfa/ns/schema#\"\n\
      xmlns:pdfaProperty=\"http://www.aiim.org/pdfa/ns/property#\">\n\
   <pdfaExtension:schemas>\n\
    <rdf:Bag>\n\
     <rdf:li rdf:parseType=\"Resource\">\n\
      <pdfaSchema:schema>PDF/UA identification schema</pdfaSchema:schema>\n\
      <pdfaSchema:namespaceURI>http://www.aiim.org/pdfua/ns/id/</pdfaSchema:namespaceURI>\n\
      <pdfaSchema:prefix>pdfuaid</pdfaSchema:prefix>\n\
      <pdfaSchema:property>\n\
       <rdf:Seq>\n\
        <rdf:li rdf:parseType=\"Resource\">\n\
         <pdfaProperty:name>part</pdfaProperty:name>\n\
         <pdfaProperty:valueType>Integer</pdfaProperty:valueType>\n\
         <pdfaProperty:category>internal</pdfaProperty:category>\n\
         <pdfaProperty:description>Indicates the type of PDF/UA conformance</pdfaProperty:description>\n\
        </rdf:li>\n\
       </rdf:Seq>\n\
      </pdfaSchema:property>\n\
     </rdf:li>\n\
    </rdf:Bag>\n\
   </pdfaExtension:schemas>\n\
  </rdf:Description>\n";

/// Build the full XMP packet bytes for `doc`.
///
/// When `claim_pdf_ua` is true the packet carries the PDF/UA-1 identifier (`pdfuaid:part=1`), a
/// `dc:description` (from `doc.subject`, when present) and the `pdfaExtension` schema description
/// for `pdfuaid`. Passing `false` yields the plain PDF/A-2U packet, byte-for-byte as before, so a
/// non-conforming document makes no UA claim.
pub fn packet(
    doc: &DocumentModel,
    metadata: &AccessibilityMetadata,
    claim_pdf_ua: bool,
) -> Vec<u8> {
    let date = iso_date(&doc.created_at);
    let title = xml_escape(&metadata.title.value);
    let lang = xml_escape(&metadata.language.value);
    let creator = xml_escape(&doc.entity_name);
    let date = xml_escape(&date);

    // PDF/UA identifier: `xmlns` declaration + `pdfuaid:part` property inside the main description,
    // emitted only for conforming documents.
    let pdfuaid_ns = if claim_pdf_ua {
        format!("      xmlns:pdfuaid=\"{PDFUAID_NS}\"\n")
    } else {
        String::new()
    };
    let pdfuaid_part = if claim_pdf_ua {
        "   <pdfuaid:part>1</pdfuaid:part>\n".to_string()
    } else {
        String::new()
    };
    // Optional UA description, reused from the subject when present.
    let description = if claim_pdf_ua && !doc.subject.trim().is_empty() {
        format!(
            "   <dc:description>\n\
    <rdf:Alt>\n\
     <rdf:li xml:lang=\"x-default\">{}</rdf:li>\n\
    </rdf:Alt>\n\
   </dc:description>\n",
            xml_escape(doc.subject.trim())
        )
    } else {
        String::new()
    };
    // Extension schema description block (a second rdf:Description), required alongside pdfuaid.
    let extension = if claim_pdf_ua {
        PDFUA_EXTENSION_SCHEMA.to_string()
    } else {
        String::new()
    };

    let xml = format!(
        "<?xpacket begin=\"\u{feff}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n\
 <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n\
  <rdf:Description rdf:about=\"\"\n\
      xmlns:pdfaid=\"http://www.aiim.org/pdfa/ns/id/\"\n\
{pdfuaid_ns}\
      xmlns:dc=\"http://purl.org/dc/elements/1.1/\"\n\
      xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"\n\
      xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\">\n\
   <pdfaid:part>2</pdfaid:part>\n\
   <pdfaid:conformance>U</pdfaid:conformance>\n\
{pdfuaid_part}\
   <dc:format>application/pdf</dc:format>\n\
   <dc:title>\n\
    <rdf:Alt>\n\
     <rdf:li xml:lang=\"x-default\">{title}</rdf:li>\n\
    </rdf:Alt>\n\
   </dc:title>\n\
{description}\
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
{extension}\
 </rdf:RDF>\n\
</x:xmpmeta>\n\
<?xpacket end=\"w\"?>",
        pdfuaid_ns = pdfuaid_ns,
        pdfuaid_part = pdfuaid_part,
        description = description,
        extension = extension,
        title = title,
        creator = creator,
        lang = lang,
        date = date,
        tool = CREATOR_TOOL,
    );
    xml.into_bytes()
}
