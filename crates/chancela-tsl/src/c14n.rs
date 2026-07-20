//! XML Canonicalization (C14N) for Trusted List XML-DSig — **wp26 E2 implementation**.
//!
//! XML-DSig signs the *canonical* form of `<ds:SignedInfo>` and of each referenced element, not the
//! raw source bytes. Real-world EU LOTL / member-state TSLs are signed over a genuine
//! canonicalization (inclusive RFC 3076 or exclusive RFC 3741), so verifying them requires
//! reconstructing those canonical bytes rather than hashing the source subtree verbatim (the
//! previous `xmldsig.rs` fast-path, correct only for already-canonical lists).
//!
//! This module is the single owner of that canonicalization. [`canonicalize`] parses one element
//! subtree with `quick-xml` and re-serialises it under the selected [`C14nAlgorithm`], applying the
//! C14N rules that matter for TSL/LOTL signatures: document-order traversal, namespace-axis
//! rendering (inclusive = all in-scope on the apex; exclusive = only visibly-utilized), attribute
//! ordering (namespace declarations first, then by namespace-URI/local-name), comment stripping,
//! empty-element expansion, and text/attribute escaping.
//!
//! # Deliberate limitations (fail loudly rather than emit wrong bytes)
//! A *wrong* canonicalization silently breaks signature verification, which is worse than a clear
//! error, so unsupported constructs are rejected with [`TslError::Canonicalization`] rather than
//! guessed: DTDs / `<!DOCTYPE>`, processing instructions inside content, and entity references
//! beyond the five predefined ones (`&amp; &lt; &gt; &quot; &apos;`) plus numeric character
//! references. In addition, XML attribute-value whitespace normalisation (XML 1.0 §3.3.3, which a
//! validating processor would apply to literal `#x9`/`#xA`/`#xD` in the *source*) is not performed:
//! after parsing, a literal whitespace character and its numeric character reference are
//! indistinguishable. Real signed TSL/LOTL attribute values (`Id`, `URI`, `Algorithm`) are simple
//! tokens with no literal whitespace, so this does not affect the target content.

use std::collections::HashMap;

use quick_xml::XmlVersion;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::error::TslError;

/// The URI of the built-in `xml` namespace prefix (RFC 3076 / XML 1.0). It is implicitly bound and
/// is never emitted as a namespace declaration.
const XML_NS_URI: &str = "http://www.w3.org/XML/1998/namespace";

/// The XML canonicalization algorithm a `<ds:CanonicalizationMethod>` / `<ds:Transform>` selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum C14nAlgorithm {
    /// Inclusive XML Canonicalization 1.0 — `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`
    /// (RFC 3076). All in-scope namespaces are emitted on the apex element.
    Inclusive,
    /// Inclusive XML Canonicalization 1.0 **with comments**
    /// (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments`).
    InclusiveWithComments,
    /// Exclusive XML Canonicalization 1.0 — `http://www.w3.org/2001/10/xml-exc-c14n#` (RFC 3741).
    /// Only visibly-utilized namespaces are emitted (plus any `InclusiveNamespaces` PrefixList).
    Exclusive,
    /// Exclusive XML Canonicalization 1.0 **with comments**
    /// (`http://www.w3.org/2001/10/xml-exc-c14n#WithComments`).
    ExclusiveWithComments,
}

impl C14nAlgorithm {
    /// Resolve a canonicalization/transform algorithm URI to a [`C14nAlgorithm`], or `None` when the
    /// URI is not a canonicalization we support.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => Some(Self::Inclusive),
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" => {
                Some(Self::InclusiveWithComments)
            }
            "http://www.w3.org/2001/10/xml-exc-c14n#" => Some(Self::Exclusive),
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => {
                Some(Self::ExclusiveWithComments)
            }
            _ => None,
        }
    }

    /// Whether this algorithm preserves comments in the canonical output.
    pub fn with_comments(self) -> bool {
        matches!(
            self,
            Self::InclusiveWithComments | Self::ExclusiveWithComments
        )
    }

    /// Whether this algorithm is exclusive canonicalization (RFC 3741).
    pub fn is_exclusive(self) -> bool {
        matches!(self, Self::Exclusive | Self::ExclusiveWithComments)
    }
}

/// Canonicalize a single XML element subtree per `algorithm`.
///
/// `element_bytes` is the serialized bytes of exactly one element (its start tag through its
/// matching end tag) **as it appears in the source document**, with the caller responsible for
/// having selected the correct subtree (for a whole-document `URI=""` reference with an
/// enveloped-signature transform, the `<ds:Signature>` element is removed first). Ancestor
/// namespace context that a real canonicalization must fold in is resolved by this function from the
/// declarations carried on the subtree; callers pass element bytes that still carry the ancestor
/// `xmlns` declarations in scope, exactly as XML-DSig requires.
///
/// Returns the canonical octet stream to be hashed. Returns [`TslError::Canonicalization`] when the
/// input is not well-formed or uses a construct this canonicalizer does not implement.
pub fn canonicalize(element_bytes: &[u8], algorithm: C14nAlgorithm) -> Result<Vec<u8>, TslError> {
    let root = parse_tree(element_bytes)?;

    // The output-ancestor context starts empty (a subtree is canonicalized as if it were its own
    // document); only the implicit `xml` prefix is pre-bound in the in-scope namespace map.
    let mut in_scope = HashMap::new();
    in_scope.insert("xml".to_owned(), XML_NS_URI.to_owned());
    let rendered = HashMap::new();

    let mut out = String::new();
    emit_element(&root, &in_scope, &rendered, algorithm, &mut out);
    Ok(out.into_bytes())
}

// ---- Parsed subtree ---------------------------------------------------------------------------

/// A node in the parsed subtree (elements, character data, comments).
enum Node {
    Element(Element),
    /// Character content (from a text run or a CDATA section), already resolved to its literal
    /// character value; re-escaped on output.
    Text(String),
    /// A comment's verbatim content (the bytes between `<!--` and `-->`).
    Comment(String),
}

/// A parsed element: its qualified name, the namespace declarations it carries, its non-namespace
/// attributes, and its child nodes in document order.
struct Element {
    qname: String,
    /// Namespace declarations literally present on this element: `(prefix, uri)` with an empty
    /// prefix meaning the default namespace (`xmlns="…"`).
    ns_decls: Vec<(String, String)>,
    /// Non-namespace attributes as `(qualified-name, value)`; the value is the resolved character
    /// value (re-escaped on output).
    attrs: Vec<(String, String)>,
    children: Vec<Node>,
}

/// Parse `element_bytes` into a single-rooted subtree, rejecting constructs this canonicalizer does
/// not implement (DTDs, processing instructions, non-predefined entity references).
fn parse_tree(element_bytes: &[u8]) -> Result<Element, TslError> {
    let mut reader = Reader::from_reader(element_bytes);
    let mut buf = Vec::new();
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;

    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| TslError::Canonicalization(format!("malformed XML: {e}")))?;
        match event {
            Event::Start(e) => {
                stack.push(build_element(&e)?);
            }
            Event::Empty(e) => {
                let el = build_element(&e)?;
                attach(&mut stack, &mut root, Node::Element(el))?;
            }
            Event::End(_) => {
                let el = stack
                    .pop()
                    .ok_or_else(|| TslError::Canonicalization("unbalanced end tag".to_owned()))?;
                attach(&mut stack, &mut root, Node::Element(el))?;
            }
            Event::Text(e) => {
                // In quick-xml 0.41 entity/character references are separate `GeneralRef` events,
                // so a `Text` event is pure literal content: decode + XML end-of-line normalization
                // (literal CR/CRLF -> LF) is all that is required.
                let text = e
                    .xml_content(XmlVersion::Implicit1_0)
                    .map_err(|err| TslError::Canonicalization(format!("bad text encoding: {err}")))?
                    .into_owned();
                attach(&mut stack, &mut root, Node::Text(text))?;
            }
            Event::GeneralRef(e) => {
                // Character reference (`&#13;`, `&#x9;`) or one of the five predefined entities.
                // Any other named entity is rejected rather than silently dropped or mis-resolved.
                let text = if let Some(ch) = e.resolve_char_ref().map_err(|err| {
                    TslError::Canonicalization(format!("bad char reference: {err}"))
                })? {
                    ch.to_string()
                } else {
                    let name = e.decode().map_err(|err| {
                        TslError::Canonicalization(format!("bad entity reference: {err}"))
                    })?;
                    match resolve_predefined_entity(&name) {
                        Some(replacement) => replacement.to_owned(),
                        None => {
                            return Err(TslError::Canonicalization(format!(
                                "unsupported entity reference &{name};"
                            )));
                        }
                    }
                };
                attach(&mut stack, &mut root, Node::Text(text))?;
            }
            Event::CData(e) => {
                // CDATA content is literal (not entity-escaped); re-escaped as ordinary text output.
                let text = e
                    .decode()
                    .map_err(|err| {
                        TslError::Canonicalization(format!("bad CDATA encoding: {err}"))
                    })?
                    .into_owned();
                attach(&mut stack, &mut root, Node::Text(text))?;
            }
            Event::Comment(e) => {
                // Comment content is emitted verbatim by C14N (no entity resolution or escaping).
                let text = e
                    .decode()
                    .map_err(|err| {
                        TslError::Canonicalization(format!("bad comment encoding: {err}"))
                    })?
                    .into_owned();
                attach(&mut stack, &mut root, Node::Comment(text))?;
            }
            Event::PI(_) => {
                return Err(TslError::Canonicalization(
                    "processing instructions are not supported".to_owned(),
                ));
            }
            Event::DocType(_) => {
                return Err(TslError::Canonicalization(
                    "DTD/DOCTYPE is not supported".to_owned(),
                ));
            }
            // An XML declaration cannot appear inside a single-element subtree; ignore if present.
            Event::Decl(_) => {}
            Event::Eof => break,
        }
        buf.clear();
    }

    if !stack.is_empty() {
        return Err(TslError::Canonicalization(
            "unbalanced start tag (missing end tag)".to_owned(),
        ));
    }
    root.ok_or_else(|| TslError::Canonicalization("no element to canonicalize".to_owned()))
}

/// Attach a node to the element currently open on the stack, or record it as top-level content.
fn attach(stack: &mut [Element], root: &mut Option<Element>, node: Node) -> Result<(), TslError> {
    if let Some(top) = stack.last_mut() {
        top.children.push(node);
        return Ok(());
    }
    // Top-level (outside the apex element). The contract is exactly one element subtree, so only
    // whitespace and comments may appear here; a second element or non-whitespace text is rejected.
    match node {
        Node::Element(e) => {
            if root.is_some() {
                return Err(TslError::Canonicalization(
                    "more than one top-level element in subtree".to_owned(),
                ));
            }
            *root = Some(e);
            Ok(())
        }
        Node::Text(t) if t.trim().is_empty() => Ok(()),
        Node::Text(_) => Err(TslError::Canonicalization(
            "character data outside the element subtree".to_owned(),
        )),
        Node::Comment(_) => Ok(()),
    }
}

/// Build an [`Element`] from a start/empty tag, splitting namespace declarations from attributes.
fn build_element(e: &quick_xml::events::BytesStart<'_>) -> Result<Element, TslError> {
    let qname = std::str::from_utf8(e.name().as_ref())
        .map_err(|_| TslError::Utf8)?
        .to_owned();

    let mut ns_decls = Vec::new();
    let mut attrs = Vec::new();
    for attr in e.attributes() {
        let attr =
            attr.map_err(|err| TslError::Canonicalization(format!("bad attribute: {err}")))?;
        let key = std::str::from_utf8(attr.key.as_ref())
            .map_err(|_| TslError::Utf8)?
            .to_owned();
        // XML attribute-value normalization (AVN, XML 1.0 §3.3.3): resolves entity/character
        // references and collapses literal whitespace to `#x20`, exactly what a conforming XML
        // processor feeds C14N.
        let value = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|err| {
                TslError::Canonicalization(format!("bad attribute value/entity: {err}"))
            })?
            .into_owned();

        if key == "xmlns" {
            ns_decls.push((String::new(), value));
        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
            ns_decls.push((prefix.to_owned(), value));
        } else {
            attrs.push((key, value));
        }
    }

    Ok(Element {
        qname,
        ns_decls,
        attrs,
        children: Vec::new(),
    })
}

// ---- Canonical emission -----------------------------------------------------------------------

/// Emit an element and its subtree in canonical form.
///
/// * `in_scope` — the true XML in-scope namespaces (`prefix -> uri`) for this element's parent.
/// * `rendered` — the namespace bindings already emitted by output ancestors.
fn emit_element(
    e: &Element,
    in_scope: &HashMap<String, String>,
    rendered: &HashMap<String, String>,
    alg: C14nAlgorithm,
    out: &mut String,
) {
    // The in-scope namespace map for this element = parent's overlaid with this element's decls.
    let mut new_in_scope = in_scope.clone();
    for (prefix, uri) in &e.ns_decls {
        if uri.is_empty() && !prefix.is_empty() {
            // Non-default prefix undeclaration (XML 1.1); remove it from scope.
            new_in_scope.remove(prefix);
        } else {
            new_in_scope.insert(prefix.clone(), uri.clone());
        }
    }

    // Decide which namespace declarations this element renders.
    let mut to_render = if alg.is_exclusive() {
        ns_to_render_exclusive(e, &new_in_scope, rendered)
    } else {
        ns_to_render_inclusive(&new_in_scope, rendered)
    };
    // Namespace declarations sort with the default (`xmlns`, empty prefix) first, then by prefix.
    to_render.sort();

    // The output-ancestor context seen by children includes what we render here.
    let mut child_rendered = rendered.clone();
    for (prefix, uri) in &to_render {
        child_rendered.insert(prefix.clone(), uri.clone());
    }

    // Start tag: name, namespace declarations, then attributes sorted by (namespace-uri, local).
    out.push('<');
    out.push_str(&e.qname);
    for (prefix, uri) in &to_render {
        if prefix.is_empty() {
            out.push_str(" xmlns=\"");
        } else {
            out.push_str(" xmlns:");
            out.push_str(prefix);
            out.push_str("=\"");
        }
        push_escaped_attr(out, uri);
        out.push('"');
    }

    let mut sorted_attrs: Vec<(String, String, String, String)> = e
        .attrs
        .iter()
        .map(|(qname, value)| {
            let (uri, local) = attr_ns_key(qname, &new_in_scope);
            (uri, local, qname.clone(), value.clone())
        })
        .collect();
    sorted_attrs.sort();
    for (_uri, _local, qname, value) in &sorted_attrs {
        out.push(' ');
        out.push_str(qname);
        out.push_str("=\"");
        push_escaped_attr(out, value);
        out.push('"');
    }
    out.push('>');

    // Children in document order.
    for child in &e.children {
        match child {
            Node::Element(child_el) => {
                emit_element(child_el, &new_in_scope, &child_rendered, alg, out);
            }
            Node::Text(text) => push_escaped_text(out, text),
            Node::Comment(text) => {
                if alg.with_comments() {
                    out.push_str("<!--");
                    out.push_str(text);
                    out.push_str("-->");
                }
            }
        }
    }

    // End tag (empty elements expand to start + end — no self-closing form).
    out.push_str("</");
    out.push_str(&e.qname);
    out.push('>');
}

/// Namespace declarations to render for an element under **inclusive** C14N: every in-scope binding
/// whose (prefix, uri) differs from the nearest output-ancestor rendering of that prefix.
fn ns_to_render_inclusive(
    new_in_scope: &HashMap<String, String>,
    rendered: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (prefix, uri) in new_in_scope {
        if prefix == "xml" {
            continue;
        }
        let current = rendered.get(prefix).map_or("", String::as_str);
        if prefix.is_empty() {
            // Default namespace. `uri == ""` (undeclaration) is only rendered when the output
            // ancestor context had a non-empty default to cancel; the `uri != current` test
            // (with absent treated as "") captures exactly that.
            if uri != current {
                out.push((prefix.clone(), uri.clone()));
            }
        } else {
            if uri.is_empty() {
                continue;
            }
            if current != uri {
                out.push((prefix.clone(), uri.clone()));
            }
        }
    }
    out
}

/// Namespace declarations to render for an element under **exclusive** C14N (no PrefixList): only
/// the namespaces "visibly utilized" by the element — its own qualified-name prefix (or the default
/// namespace when the element is unprefixed) and the prefix of each namespaced attribute — that are
/// not already output by an ancestor with the same prefix and URI.
fn ns_to_render_exclusive(
    e: &Element,
    new_in_scope: &HashMap<String, String>,
    rendered: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut utilized: Vec<String> = Vec::new();
    // The element's own prefix (empty string = it uses the default namespace).
    utilized.push(prefix_of(&e.qname).to_owned());
    // Attribute prefixes; unprefixed attributes are in no namespace and utilize nothing.
    for (qname, _) in &e.attrs {
        if let Some((prefix, _)) = qname.split_once(':') {
            utilized.push(prefix.to_owned());
        }
    }
    utilized.sort();
    utilized.dedup();

    let mut out = Vec::new();
    for prefix in utilized {
        if prefix == "xml" {
            continue;
        }
        let uri = new_in_scope.get(&prefix).map_or("", String::as_str);
        let current = rendered.get(&prefix).map_or("", String::as_str);
        if prefix.is_empty() {
            // Default namespace: render when it differs from the rendered default (including
            // rendering `xmlns=""` to move an unprefixed element out of an inherited default).
            if uri != current {
                out.push((prefix, uri.to_owned()));
            }
        } else {
            if uri.is_empty() {
                // Prefix used but not bound in scope — malformed; skip rather than emit garbage.
                continue;
            }
            if current != uri {
                out.push((prefix, uri.to_owned()));
            }
        }
    }
    out
}

/// The prefix portion of a qualified name (`""` when there is no prefix).
fn prefix_of(qname: &str) -> &str {
    qname.split_once(':').map_or("", |(prefix, _)| prefix)
}

/// The C14N attribute sort key: `(namespace-uri, local-name)`. Unprefixed attributes are in no
/// namespace (empty URI), which sorts before any namespaced attribute.
fn attr_ns_key(qname: &str, in_scope: &HashMap<String, String>) -> (String, String) {
    match qname.split_once(':') {
        Some((prefix, local)) => {
            let uri = in_scope.get(prefix).cloned().unwrap_or_default();
            (uri, local.to_owned())
        }
        None => (String::new(), qname.to_owned()),
    }
}

/// Escape a character value for an attribute value delimited by `"` (C14N §"Attribute Nodes"):
/// `&`, `<`, `"`, and the whitespace characters `#x9`, `#xA`, `#xD`. `>` is **not** escaped.
fn push_escaped_attr(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(ch),
        }
    }
}

/// Escape a character value in element text content (C14N §"Text Nodes"): `&`, `<`, `>`, and `#xD`.
/// Tabs and newlines are preserved literally.
fn push_escaped_text(out: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(ch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Convenience: canonicalize `xml` and return the result as a `String`.
    fn c14n(xml: &str, alg: C14nAlgorithm) -> String {
        String::from_utf8(canonicalize(xml.as_bytes(), alg).expect("canonicalization succeeds"))
            .expect("canonical output is UTF-8")
    }

    #[test]
    fn already_canonical_element_round_trips_inclusive() {
        let xml = r#"<Foo xmlns="urn:x"><Bar>hi</Bar></Foo>"#;
        assert_eq!(c14n(xml, C14nAlgorithm::Inclusive), xml);
    }

    #[test]
    fn attributes_are_sorted() {
        // Input attributes in non-canonical order emit sorted by (namespace-uri, local-name).
        let xml = r#"<e b="2" a="1" c="3"/>"#;
        assert_eq!(
            c14n(xml, C14nAlgorithm::Inclusive),
            r#"<e a="1" b="2" c="3"></e>"#
        );
    }

    #[test]
    fn namespaced_attributes_sort_by_uri_then_local() {
        // No-namespace attribute sorts first; namespaced ones by URI then local name.
        let xml = r#"<e xmlns:p="urn:p" xmlns:q="urn:q" p:z="1" q:a="2" m="0"/>"#;
        assert_eq!(
            c14n(xml, C14nAlgorithm::Inclusive),
            r#"<e xmlns:p="urn:p" xmlns:q="urn:q" m="0" p:z="1" q:a="2"></e>"#
        );
    }

    #[test]
    fn empty_element_expands_to_start_end() {
        assert_eq!(c14n("<a/>", C14nAlgorithm::Inclusive), "<a></a>");
        assert_eq!(
            c14n("<a></a>", C14nAlgorithm::Inclusive),
            "<a></a>",
            "already-expanded form is stable"
        );
    }

    #[test]
    fn comments_stripped_unless_with_comments() {
        let xml = "<a><!-- keep? --></a>";
        assert_eq!(c14n(xml, C14nAlgorithm::Inclusive), "<a></a>");
        assert_eq!(
            c14n(xml, C14nAlgorithm::InclusiveWithComments),
            "<a><!-- keep? --></a>"
        );
        // Exclusive follows the same comment rule.
        assert_eq!(c14n(xml, C14nAlgorithm::Exclusive), "<a></a>");
        assert_eq!(
            c14n(xml, C14nAlgorithm::ExclusiveWithComments),
            "<a><!-- keep? --></a>"
        );
    }

    #[test]
    fn text_special_characters_are_escaped() {
        // Source entity refs resolve to characters, then re-escape per C14N text rules.
        let xml = "<a>&amp;&lt;&gt;</a>";
        assert_eq!(c14n(xml, C14nAlgorithm::Inclusive), "<a>&amp;&lt;&gt;</a>");
    }

    #[test]
    fn text_preserves_whitespace_but_escapes_cr() {
        let xml = "<a>  x\t&#13;\n </a>";
        // Tab and newline preserved; carriage return escaped to &#xD;.
        assert_eq!(c14n(xml, C14nAlgorithm::Inclusive), "<a>  x\t&#xD;\n </a>");
    }

    #[test]
    fn attribute_special_characters_are_escaped() {
        // `&#9;` -> tab -> `&#x9;`; `&` `<` `"` escaped; `>` left as-is in an attribute value.
        let xml = r#"<a x="&amp;&lt;&quot;&#9;&gt;"/>"#;
        assert_eq!(
            c14n(xml, C14nAlgorithm::Inclusive),
            r#"<a x="&amp;&lt;&quot;&#x9;>"></a>"#
        );
    }

    #[test]
    fn cdata_becomes_escaped_text() {
        let xml = "<a><![CDATA[a < b & c]]></a>";
        assert_eq!(
            c14n(xml, C14nAlgorithm::Inclusive),
            "<a>a &lt; b &amp; c</a>"
        );
    }

    #[test]
    fn inclusive_emits_unused_ancestor_namespace_exclusive_drops_it() {
        // Apex carries an in-scope-but-unused prefix `unused` plus the used prefix `used`.
        let xml = r#"<used:Root xmlns:unused="urn:u" xmlns:used="urn:s"><used:Child>t</used:Child></used:Root>"#;

        // Inclusive renders every in-scope namespace on the apex (sorted by prefix).
        assert_eq!(
            c14n(xml, C14nAlgorithm::Inclusive),
            r#"<used:Root xmlns:unused="urn:u" xmlns:used="urn:s"><used:Child>t</used:Child></used:Root>"#
        );

        // Exclusive renders only visibly-utilized namespaces: `unused` is dropped.
        assert_eq!(
            c14n(xml, C14nAlgorithm::Exclusive),
            r#"<used:Root xmlns:used="urn:s"><used:Child>t</used:Child></used:Root>"#
        );
    }

    #[test]
    fn exclusive_floats_namespace_down_to_first_use() {
        // Prefix `p` declared on the apex but first *used* on the child: exclusive emits it there.
        let xml = r#"<Root xmlns:p="urn:p"><p:Child/></Root>"#;
        assert_eq!(
            c14n(xml, C14nAlgorithm::Exclusive),
            r#"<Root><p:Child xmlns:p="urn:p"></p:Child></Root>"#
        );
        // Inclusive keeps it on the apex.
        assert_eq!(
            c14n(xml, C14nAlgorithm::Inclusive),
            r#"<Root xmlns:p="urn:p"><p:Child></p:Child></Root>"#
        );
    }

    #[test]
    fn exclusive_default_namespace_only_when_element_unprefixed() {
        // Default namespace is visibly utilized by the unprefixed child, emitted there, and not
        // superfluously repeated on the grandchild.
        let xml = r#"<r:Root xmlns:r="urn:r" xmlns="urn:d"><Child><Grand/></Child></r:Root>"#;
        assert_eq!(
            c14n(xml, C14nAlgorithm::Exclusive),
            r#"<r:Root xmlns:r="urn:r"><Child xmlns="urn:d"><Grand></Grand></Child></r:Root>"#
        );
    }

    #[test]
    fn inclusive_drops_superfluous_child_redeclaration() {
        // Child redeclares a prefix identical to an in-scope ancestor binding: dropped in inclusive.
        let xml = r#"<a:Root xmlns:a="urn:a"><a:Child xmlns:a="urn:a">t</a:Child></a:Root>"#;
        assert_eq!(
            c14n(xml, C14nAlgorithm::Inclusive),
            r#"<a:Root xmlns:a="urn:a"><a:Child>t</a:Child></a:Root>"#
        );
    }

    #[test]
    fn namespace_declarations_precede_attributes_and_sort() {
        // Declarations come first (default `xmlns` before prefixed), then attributes.
        let xml = r#"<e z="1" xmlns:b="urn:b" xmlns="urn:d" xmlns:a="urn:a"/>"#;
        assert_eq!(
            c14n(xml, C14nAlgorithm::Inclusive),
            r#"<e xmlns="urn:d" xmlns:a="urn:a" xmlns:b="urn:b" z="1"></e>"#
        );
    }

    #[test]
    fn dtd_and_processing_instructions_are_rejected() {
        assert!(matches!(
            canonicalize(b"<a><?pi data?></a>", C14nAlgorithm::Inclusive),
            Err(TslError::Canonicalization(_))
        ));
        assert!(matches!(
            canonicalize(b"<!DOCTYPE a><a/>", C14nAlgorithm::Inclusive),
            Err(TslError::Canonicalization(_))
        ));
    }

    #[test]
    fn undefined_entity_reference_is_rejected() {
        assert!(matches!(
            canonicalize(b"<a>&custom;</a>", C14nAlgorithm::Inclusive),
            Err(TslError::Canonicalization(_))
        ));
    }

    #[test]
    fn malformed_xml_is_rejected() {
        assert!(matches!(
            canonicalize(b"<a><b></a>", C14nAlgorithm::Inclusive),
            Err(TslError::Canonicalization(_))
        ));
    }

    #[test]
    fn from_uri_resolves_all_four_algorithms_and_none() {
        assert_eq!(
            C14nAlgorithm::from_uri("http://www.w3.org/TR/2001/REC-xml-c14n-20010315"),
            Some(C14nAlgorithm::Inclusive)
        );
        assert_eq!(
            C14nAlgorithm::from_uri("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"),
            Some(C14nAlgorithm::InclusiveWithComments)
        );
        assert_eq!(
            C14nAlgorithm::from_uri("http://www.w3.org/2001/10/xml-exc-c14n#"),
            Some(C14nAlgorithm::Exclusive)
        );
        assert_eq!(
            C14nAlgorithm::from_uri("http://www.w3.org/2001/10/xml-exc-c14n#WithComments"),
            Some(C14nAlgorithm::ExclusiveWithComments)
        );
        assert_eq!(
            C14nAlgorithm::from_uri("http://www.w3.org/2000/09/xmldsig#sha1"),
            None
        );
    }

    #[test]
    fn with_comments_and_is_exclusive_flags() {
        assert!(!C14nAlgorithm::Inclusive.with_comments());
        assert!(C14nAlgorithm::InclusiveWithComments.with_comments());
        assert!(!C14nAlgorithm::Inclusive.is_exclusive());
        assert!(C14nAlgorithm::Exclusive.is_exclusive());
        assert!(C14nAlgorithm::ExclusiveWithComments.is_exclusive());
    }

    #[test]
    fn signedinfo_like_subtree_canonicalizes_exclusively() {
        // A realistic exclusive-C14N SignedInfo shape: only the used `ds` prefix is emitted, the
        // apex declaration is inherited by descendants without repetition, and empty elements expand.
        let xml = r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo>"#;
        let expected = r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI=""><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo>"#;
        assert_eq!(c14n(xml, C14nAlgorithm::Exclusive), expected);
    }
}
