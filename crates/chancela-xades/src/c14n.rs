//! Exclusive XML Canonicalization (excl-c14n, W3C REC) + inclusive Canonical XML 1.0.
//!
//! This is the single highest-risk deliverable of the crate: XMLDSig/XAdES require a byte-exact
//! canonical form over `SignedInfo` and every `Reference`, and a wrong canonicalization makes a
//! signature that no third-party validator (Apache Santuario/xmlsec, EU DSS) will accept. It is
//! implemented in-crate and gated on a committed reference-vector suite (`tests/c14n_vectors.rs`
//! over `tests/fixtures/c14n/**`) which must pass before any XAdES level machinery is trusted. See
//! `.orchestration/plans/t67.md` §0.2.
//!
//! # Why not roxmltree
//!
//! The plan sketch names `roxmltree` for this module, but canonicalization is **prefix-sensitive**
//! (`<n1:e xmlns:n1="X"/>` and `<n2:e xmlns:n2="X"/>` have distinct canonical forms) and
//! `roxmltree`'s public API exposes only the *resolved* namespace URI of an element/attribute, not
//! the original prefix it was written with. Canonicalization must reproduce the exact prefixes, so
//! this module parses over `quick-xml`'s low-level raw event stream (which preserves prefixes and
//! source attribute order) into a small internal DOM, and canonicalizes over that. `quick-xml` is
//! already a pinned workspace dependency; no new third-party crate is added. `roxmltree` is still
//! used elsewhere in the crate for read-only tree navigation where the crate controls the prefixes.
//!
//! # Algorithms
//!
//! - Exclusive C14N (`http://www.w3.org/2001/10/xml-exc-c14n#`) with `InclusiveNamespaces`
//!   PrefixList support — the XAdES/ASiC default.
//! - Inclusive Canonical XML 1.0 (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`) — needed by
//!   some transforms.
//!
//! Both are offered in with- and without-comments variants; XMLDSig uses the without-comments form.

use std::collections::{BTreeMap, HashSet};

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::error::XadesError;

/// The XML canonicalization algorithm to apply.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum C14nAlgorithm {
    /// `http://www.w3.org/2001/10/xml-exc-c14n#` — exclusive, comments omitted (the XMLDSig default).
    ExclusiveWithoutComments,
    /// `http://www.w3.org/2001/10/xml-exc-c14n#WithComments` — exclusive, comments retained.
    ExclusiveWithComments,
    /// `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` — inclusive C14N 1.0, comments omitted.
    InclusiveWithoutComments,
    /// `http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments` — inclusive, comments retained.
    InclusiveWithComments,
}

impl C14nAlgorithm {
    /// The W3C algorithm identifier URI (as it appears in a `CanonicalizationMethod`/`Transform`).
    pub fn uri(self) -> &'static str {
        match self {
            C14nAlgorithm::ExclusiveWithoutComments => "http://www.w3.org/2001/10/xml-exc-c14n#",
            C14nAlgorithm::ExclusiveWithComments => {
                "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
            }
            C14nAlgorithm::InclusiveWithoutComments => {
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            }
            C14nAlgorithm::InclusiveWithComments => {
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
            }
        }
    }

    /// Resolve a canonicalization/transform algorithm URI to the enum, if supported.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "http://www.w3.org/2001/10/xml-exc-c14n#" => Some(Self::ExclusiveWithoutComments),
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => {
                Some(Self::ExclusiveWithComments)
            }
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => {
                Some(Self::InclusiveWithoutComments)
            }
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" => {
                Some(Self::InclusiveWithComments)
            }
            _ => None,
        }
    }

    fn is_exclusive(self) -> bool {
        matches!(
            self,
            C14nAlgorithm::ExclusiveWithoutComments | C14nAlgorithm::ExclusiveWithComments
        )
    }

    fn with_comments(self) -> bool {
        matches!(
            self,
            C14nAlgorithm::ExclusiveWithComments | C14nAlgorithm::InclusiveWithComments
        )
    }
}

/// The predefined `xml` prefix namespace URI (XML 1.0 §2.3); implicitly always in scope.
const XML_NS_URI: &str = "http://www.w3.org/XML/1998/namespace";

// ------------------------------------------------------------------------------------------------
// Internal DOM (prefix-preserving, source attribute order)
// ------------------------------------------------------------------------------------------------

type NodeId = usize;

#[derive(Debug)]
struct ElementData {
    /// The namespace prefix as written (`None` = no prefix).
    prefix: Option<String>,
    local: String,
    /// Namespace declarations on this element, in source order. `None` prefix = the default (`xmlns`).
    ns_decls: Vec<(Option<String>, String)>,
    /// Non-namespace attributes, in source order, values already normalized + unescaped.
    attrs: Vec<AttrData>,
    children: Vec<NodeId>,
    parent: Option<NodeId>,
}

#[derive(Debug)]
struct AttrData {
    prefix: Option<String>,
    local: String,
    /// Normalized, unescaped attribute value (character data).
    value: String,
}

#[derive(Debug)]
enum Node {
    Element(ElementData),
    /// Character data (already unescaped; CDATA folded to text).
    Text(String),
    Comment(String),
    Pi {
        target: String,
        data: String,
    },
}

/// A parsed document with a prefix-preserving arena, suitable for canonicalization.
pub(crate) struct Dom {
    arena: Vec<Node>,
    /// Top-level nodes in document order (the root element plus any prolog/epilog comments/PIs).
    top_level: Vec<NodeId>,
}

impl Dom {
    fn elem(&self, id: NodeId) -> &ElementData {
        match &self.arena[id] {
            Node::Element(e) => e,
            _ => unreachable!("node {id} is not an element"),
        }
    }

    /// Resolve the element carrying `Id="id"` (the XMLDSig id attribute), fail-closed on ambiguity.
    ///
    /// XML Signature dereferences an `Id` for every `#id` reference and for the enveloped-transform
    /// exclusion. A duplicate `Id` makes that dereference ambiguous and is the lever for
    /// signature-wrapping (XSW): the validator digests one element while a downstream consumer reads
    /// another. Rather than silently pick the first match, resolution returns an error when more than
    /// one element carries the value.
    pub(crate) fn find_by_id(&self, id: &str) -> Result<Option<NodeId>, XadesError> {
        let mut found: Option<NodeId> = None;
        for nid in 0..self.arena.len() {
            if let Node::Element(e) = &self.arena[nid] {
                let carries = e
                    .attrs
                    .iter()
                    .any(|a| a.prefix.is_none() && a.local == "Id" && a.value == id);
                if carries {
                    if found.is_some() {
                        return Err(XadesError::Canonicalization(format!(
                            "ambiguous Id \"{id}\" resolves to multiple elements"
                        )));
                    }
                    found = Some(nid);
                }
            }
        }
        Ok(found)
    }

    /// Reject a document in which more than one element carries the same XMLDSig `Id` value.
    ///
    /// A document-wide fail-closed scan run at validation entry, complementing the per-resolution
    /// check in [`Self::find_by_id`]: it catches a duplicate planted on an element that no
    /// `Reference` happens to dereference, closing the signature-wrapping surface completely.
    pub(crate) fn check_unique_ids(&self) -> Result<(), XadesError> {
        let mut seen: HashSet<&str> = HashSet::new();
        for node in &self.arena {
            if let Node::Element(e) = node {
                for a in &e.attrs {
                    if a.prefix.is_none() && a.local == "Id" && !seen.insert(a.value.as_str()) {
                        return Err(XadesError::Canonicalization(format!(
                            "duplicate Id \"{}\" — document rejected (signature-wrapping guard)",
                            a.value
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// The in-scope namespace mapping visible to `node` from its ancestors (excluding the node's
    /// own declarations). `""` key = default namespace (value `""` means "no default namespace").
    fn ancestor_scope(&self, node: NodeId) -> BTreeMap<String, String> {
        let mut chain = Vec::new();
        let mut cur = self.elem(node).parent;
        while let Some(p) = cur {
            chain.push(p);
            cur = self.elem(p).parent;
        }
        chain.reverse();
        let mut scope = BTreeMap::new();
        for anc in chain {
            for (pfx, uri) in &self.elem(anc).ns_decls {
                scope.insert(pfx.clone().unwrap_or_default(), uri.clone());
            }
        }
        scope
    }
}

// ------------------------------------------------------------------------------------------------
// Parsing (quick-xml raw events -> Dom)
// ------------------------------------------------------------------------------------------------

/// Normalize line endings per XML 1.0 §2.11 on the raw bytes (`\r\n` and lone `\r` -> `\n`).
/// Done before parsing so that literal end-of-line characters collapse while numeric character
/// references such as `&#xD;` (still literal text at this stage) survive to denote a real CR.
fn normalize_line_endings(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'\r' => {
                out.push(b'\n');
                if i + 1 < input.len() && input[i + 1] == b'\n' {
                    i += 1;
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    out
}

/// Unescape the five predefined XML entities and numeric character references into `out`.
fn unescape_into(raw: &str, out: &mut String) -> Result<(), XadesError> {
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            let end = raw[i..].find(';').map(|off| i + off).ok_or_else(|| {
                XadesError::Canonicalization("unterminated entity reference".into())
            })?;
            let ent = &raw[i + 1..end];
            match ent {
                "amp" => out.push('&'),
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "quot" => out.push('"'),
                "apos" => out.push('\''),
                _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                    let cp = u32::from_str_radix(&ent[2..], 16).map_err(|_| {
                        XadesError::Canonicalization(format!("bad char ref &{ent};"))
                    })?;
                    out.push(char::from_u32(cp).ok_or_else(|| {
                        XadesError::Canonicalization(format!("invalid code point &{ent};"))
                    })?);
                }
                _ if ent.starts_with('#') => {
                    let cp = ent[1..].parse::<u32>().map_err(|_| {
                        XadesError::Canonicalization(format!("bad char ref &{ent};"))
                    })?;
                    out.push(char::from_u32(cp).ok_or_else(|| {
                        XadesError::Canonicalization(format!("invalid code point &{ent};"))
                    })?);
                }
                other => {
                    return Err(XadesError::Canonicalization(format!(
                        "unsupported entity reference &{other};"
                    )));
                }
            }
            i = end + 1;
        } else {
            let ch = raw[i..].chars().next().expect("non-empty");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    Ok(())
}

/// Normalize an attribute value per XML 1.0 §3.3.3 (CDATA-type): literal whitespace becomes a
/// space, then entity/character references are expanded. Line endings are already normalized on the
/// whole input, so only `\t`/`\n` remain to collapse; a `&#x9;`/`&#xA;`/`&#xD;` reference survives
/// expansion and denotes a real control character.
fn normalize_attr_value(raw: &str) -> Result<String, XadesError> {
    let mut collapsed = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\t' | '\n' => collapsed.push(' '),
            other => collapsed.push(other),
        }
    }
    let mut out = String::with_capacity(collapsed.len());
    unescape_into(&collapsed, &mut out)?;
    Ok(out)
}

fn split_qname(qname: &[u8]) -> Result<(Option<String>, String), XadesError> {
    let s = std::str::from_utf8(qname).map_err(|_| XadesError::XmlParse("non-utf8 name".into()))?;
    match s.split_once(':') {
        Some((pfx, local)) => Ok((Some(pfx.to_string()), local.to_string())),
        None => Ok((None, s.to_string())),
    }
}

/// Build an [`ElementData`] (without children) from a `quick-xml` start/empty tag, splitting
/// namespace declarations from ordinary attributes and normalizing attribute values.
fn build_element(
    e: &quick_xml::events::BytesStart<'_>,
    parent: Option<NodeId>,
) -> Result<ElementData, XadesError> {
    let (prefix, local) = split_qname(e.name().as_ref())?;
    let mut ns_decls = Vec::new();
    let mut attrs = Vec::new();
    for a in e.attributes() {
        let a = a.map_err(|err| XadesError::XmlParse(err.to_string()))?;
        let key = a.key.as_ref();
        let raw_val = std::str::from_utf8(&a.value)
            .map_err(|_| XadesError::XmlParse("non-utf8 attribute value".into()))?
            .to_string();
        if key == b"xmlns" {
            let mut uri = String::new();
            unescape_into(&raw_val, &mut uri)?;
            ns_decls.push((None, uri));
        } else if key.starts_with(b"xmlns:") {
            let pfx = std::str::from_utf8(&key[6..])
                .map_err(|_| XadesError::XmlParse("non-utf8 ns prefix".into()))?
                .to_string();
            let mut uri = String::new();
            unescape_into(&raw_val, &mut uri)?;
            ns_decls.push((Some(pfx), uri));
        } else {
            let (apfx, alocal) = split_qname(key)?;
            attrs.push(AttrData {
                prefix: apfx,
                local: alocal,
                value: normalize_attr_value(&raw_val)?,
            });
        }
    }
    Ok(ElementData {
        prefix,
        local,
        ns_decls,
        attrs,
        children: Vec::new(),
        parent,
    })
}

fn push_node(
    arena: &mut Vec<Node>,
    stack: &[NodeId],
    top_level: &mut Vec<NodeId>,
    node: Node,
) -> NodeId {
    let id = arena.len();
    arena.push(node);
    if let Some(&parent) = stack.last() {
        if let Node::Element(e) = &mut arena[parent] {
            e.children.push(id);
        }
    } else {
        top_level.push(id);
    }
    id
}

pub(crate) fn parse(xml: &[u8]) -> Result<Dom, XadesError> {
    let normalized = normalize_line_endings(xml);
    let text = std::str::from_utf8(&normalized)
        .map_err(|_| XadesError::XmlParse("input is not valid UTF-8".into()))?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text_start = false;
    reader.config_mut().trim_text_end = false;
    reader.config_mut().expand_empty_elements = false;
    reader.config_mut().check_end_names = true;

    let mut arena: Vec<Node> = Vec::new();
    let mut top_level: Vec<NodeId> = Vec::new();
    let mut stack: Vec<NodeId> = Vec::new();

    loop {
        match reader
            .read_event()
            .map_err(|e| XadesError::XmlParse(e.to_string()))?
        {
            Event::Eof => break,
            Event::Decl(_) | Event::DocType(_) => { /* removed by canonicalization */ }
            Event::Start(e) => {
                let parent = stack.last().copied();
                let node = Node::Element(build_element(&e, parent)?);
                let id = push_node(&mut arena, &stack, &mut top_level, node);
                stack.push(id);
            }
            Event::Empty(e) => {
                // An empty element has no matching `End`; do not keep it on the open-element stack.
                let parent = stack.last().copied();
                let node = Node::Element(build_element(&e, parent)?);
                push_node(&mut arena, &stack, &mut top_level, node);
            }
            Event::End(_) => {
                stack.pop();
            }
            Event::Text(t) => {
                let raw = std::str::from_utf8(&t)
                    .map_err(|_| XadesError::XmlParse("non-utf8 text".into()))?
                    .to_string();
                let mut unescaped = String::with_capacity(raw.len());
                unescape_into(&raw, &mut unescaped)?;
                push_node(&mut arena, &stack, &mut top_level, Node::Text(unescaped));
            }
            Event::CData(c) => {
                // CDATA content is literal (no entity expansion); canonicalization re-escapes it as
                // ordinary character data.
                let raw = std::str::from_utf8(&c)
                    .map_err(|_| XadesError::XmlParse("non-utf8 cdata".into()))?
                    .to_string();
                push_node(&mut arena, &stack, &mut top_level, Node::Text(raw));
            }
            Event::GeneralRef(r) => {
                // `quick-xml` reports `&lt;`, `&amp;`, `&#xD;`, … in character content as standalone
                // reference events. Resolve to the referenced character(s) as an adjacent text node
                // (canonical output concatenates adjacent character data).
                let name = std::str::from_utf8(r.as_ref())
                    .map_err(|_| XadesError::XmlParse("non-utf8 entity reference".into()))?;
                let mut resolved = String::new();
                unescape_into(&format!("&{name};"), &mut resolved)?;
                push_node(&mut arena, &stack, &mut top_level, Node::Text(resolved));
            }
            Event::Comment(c) => {
                let raw = std::str::from_utf8(&c)
                    .map_err(|_| XadesError::XmlParse("non-utf8 comment".into()))?
                    .to_string();
                push_node(&mut arena, &stack, &mut top_level, Node::Comment(raw));
            }
            Event::PI(p) => {
                let whole = std::str::from_utf8(p.as_ref())
                    .map_err(|_| XadesError::XmlParse("non-utf8 pi".into()))?;
                let (target, data) = match whole.find(|c: char| c.is_ascii_whitespace()) {
                    Some(idx) => (whole[..idx].to_string(), whole[idx + 1..].to_string()),
                    None => (whole.to_string(), String::new()),
                };
                push_node(
                    &mut arena,
                    &stack,
                    &mut top_level,
                    Node::Pi { target, data },
                );
            }
        }
    }

    if !top_level
        .iter()
        .any(|&id| matches!(arena[id], Node::Element(_)))
    {
        return Err(XadesError::XmlParse("document has no root element".into()));
    }

    Ok(Dom { arena, top_level })
}

// ------------------------------------------------------------------------------------------------
// Canonicalization
// ------------------------------------------------------------------------------------------------

/// Canonicalize the whole document.
pub fn canonicalize_document(
    xml: &[u8],
    alg: C14nAlgorithm,
    inclusive_prefixes: &[&str],
) -> Result<Vec<u8>, XadesError> {
    let dom = parse(xml)?;
    Ok(dom.canonicalize_document(alg, inclusive_prefixes, &HashSet::new()))
}

/// Parse `xml` and fail closed if any XMLDSig `Id` value is carried by more than one element.
///
/// XML Signature reference resolution (`#id`) and the enveloped-transform exclusion both dereference
/// an `Id`; a duplicate `Id` makes that dereference ambiguous and is the lever for signature-wrapping
/// (XSW) attacks. Callers run this at validation entry so an ambiguous document is rejected outright
/// rather than validated against a first-match guess.
pub fn check_unique_ids(xml: &[u8]) -> Result<(), XadesError> {
    parse(xml)?.check_unique_ids()
}

/// Parse `xml` and canonicalize the single element carrying `Id="id"` (the common XMLDSig case:
/// canonicalizing `SignedInfo`, `SignedProperties`, or a referenced `Object`).
pub fn canonicalize_element_by_id(
    xml: &[u8],
    id: &str,
    alg: C14nAlgorithm,
    inclusive_prefixes: &[&str],
) -> Result<Vec<u8>, XadesError> {
    let dom = parse(xml)?;
    let node = dom
        .find_by_id(id)?
        .ok_or_else(|| XadesError::Canonicalization(format!("no element with Id=\"{id}\"")))?;
    Ok(dom.canonicalize_subtree(node, alg, inclusive_prefixes, &HashSet::new()))
}

/// Canonicalize the whole document with the elements carrying the given `Id`s (and their subtrees)
/// omitted — the realization of the enveloped-signature transform, which strips the enclosing
/// `<ds:Signature>` before canonicalizing.
pub fn canonicalize_document_excluding_ids(
    xml: &[u8],
    exclude_ids: &[&str],
    alg: C14nAlgorithm,
    inclusive_prefixes: &[&str],
) -> Result<Vec<u8>, XadesError> {
    let dom = parse(xml)?;
    let mut omit = HashSet::new();
    for id in exclude_ids {
        if let Some(nid) = dom.find_by_id(id)? {
            omit.insert(nid);
        }
    }
    Ok(dom.canonicalize_document(alg, inclusive_prefixes, &omit))
}

impl Dom {
    /// Canonicalize the document, honoring the prolog/epilog comment & PI placement rules. Elements
    /// whose node id is in `omit` (and their subtrees) are excluded.
    pub(crate) fn canonicalize_document(
        &self,
        alg: C14nAlgorithm,
        inclusive_prefixes: &[&str],
        omit: &HashSet<NodeId>,
    ) -> Vec<u8> {
        let incl: Vec<String> = inclusive_prefixes.iter().map(|s| s.to_string()).collect();
        let mut out = String::new();
        let mut seen_root = false;
        for &nid in &self.top_level {
            match &self.arena[nid] {
                Node::Element(_) => {
                    self.emit_element(
                        nid,
                        &BTreeMap::new(),
                        &BTreeMap::new(),
                        alg,
                        &incl,
                        omit,
                        &mut out,
                    );
                    seen_root = true;
                }
                Node::Comment(c) => {
                    if alg.with_comments() {
                        if seen_root {
                            out.push('\n');
                        }
                        out.push_str("<!--");
                        out.push_str(c);
                        out.push_str("-->");
                        if !seen_root {
                            out.push('\n');
                        }
                    }
                }
                Node::Pi { target, data } => {
                    if seen_root {
                        out.push('\n');
                    }
                    emit_pi(target, data, &mut out);
                    if !seen_root {
                        out.push('\n');
                    }
                }
                Node::Text(_) => { /* whitespace outside the root element is discarded */ }
            }
        }
        out.into_bytes()
    }

    /// Canonicalize the subtree rooted at `node`, treating it as the apex (its in-scope ancestor
    /// namespaces are rendered as required by the algorithm). `omit` names element node ids whose
    /// entire subtree is excluded (used to realize the enveloped-signature transform).
    pub(crate) fn canonicalize_subtree(
        &self,
        node: NodeId,
        alg: C14nAlgorithm,
        inclusive_prefixes: &[&str],
        omit: &HashSet<NodeId>,
    ) -> Vec<u8> {
        let incl: Vec<String> = inclusive_prefixes.iter().map(|s| s.to_string()).collect();
        let ancestor_scope = self.ancestor_scope(node);
        let mut out = String::new();
        self.emit_element(
            node,
            &ancestor_scope,
            &BTreeMap::new(),
            alg,
            &incl,
            omit,
            &mut out,
        );
        out.into_bytes()
    }

    /// Emit one element and its descendants.
    ///
    /// - `scope` is the actual in-scope namespace mapping inherited from ancestors (prefix -> uri;
    ///   `""` = default, value `""` = no default namespace).
    /// - `rendered` is the namespace mapping already written into the canonical output by ancestors.
    #[allow(clippy::too_many_arguments)]
    fn emit_element(
        &self,
        id: NodeId,
        scope: &BTreeMap<String, String>,
        rendered: &BTreeMap<String, String>,
        alg: C14nAlgorithm,
        inclusive_prefixes: &[String],
        omit: &HashSet<NodeId>,
        out: &mut String,
    ) {
        let e = self.elem(id);

        // 1. New in-scope mapping = inherited scope overlaid with this element's declarations.
        let mut new_scope = scope.clone();
        for (pfx, uri) in &e.ns_decls {
            new_scope.insert(pfx.clone().unwrap_or_default(), uri.clone());
        }

        // 2. Decide which namespace declarations to render.
        let to_render = if alg.is_exclusive() {
            self.exclusive_ns_to_render(e, &new_scope, rendered, inclusive_prefixes)
        } else {
            inclusive_ns_to_render(&new_scope, rendered)
        };

        // 3. The rendered namespace set visible to children.
        let mut child_rendered = rendered.clone();
        for (pfx, uri) in &to_render {
            child_rendered.insert(pfx.clone(), uri.clone());
        }

        // 4. Start tag.
        let qname = qualified_name(&e.prefix, &e.local);
        out.push('<');
        out.push_str(&qname);

        // Namespace declarations, sorted: default (`xmlns`) first, then by prefix.
        let mut ns_sorted = to_render;
        ns_sorted.sort_by(|a, b| a.0.cmp(&b.0));
        for (pfx, uri) in &ns_sorted {
            if pfx.is_empty() {
                out.push_str(" xmlns=\"");
            } else {
                out.push_str(" xmlns:");
                out.push_str(pfx);
                out.push_str("=\"");
            }
            escape_attr(uri, out);
            out.push('"');
        }

        // Attributes, sorted by (namespace uri, local name); unprefixed => empty uri sorts first.
        let mut attrs_sorted: Vec<&AttrData> = e.attrs.iter().collect();
        attrs_sorted.sort_by(|a, b| {
            let ua = attr_ns_uri(a, &new_scope);
            let ub = attr_ns_uri(b, &new_scope);
            (ua, &a.local).cmp(&(ub, &b.local))
        });
        for a in attrs_sorted {
            out.push(' ');
            out.push_str(&qualified_name(&a.prefix, &a.local));
            out.push_str("=\"");
            escape_attr(&a.value, out);
            out.push('"');
        }
        out.push('>');

        // 5. Children.
        for &cid in &e.children {
            if omit.contains(&cid) {
                continue;
            }
            match &self.arena[cid] {
                Node::Element(_) => self.emit_element(
                    cid,
                    &new_scope,
                    &child_rendered,
                    alg,
                    inclusive_prefixes,
                    omit,
                    out,
                ),
                Node::Text(t) => escape_text(t, out),
                Node::Comment(c) => {
                    if alg.with_comments() {
                        out.push_str("<!--");
                        out.push_str(c);
                        out.push_str("-->");
                    }
                }
                Node::Pi { target, data } => emit_pi(target, data, out),
            }
        }

        // 6. End tag (empty elements are always written as a start/end pair).
        out.push_str("</");
        out.push_str(&qname);
        out.push('>');
    }

    /// Exclusive-c14n namespace rendering: render a namespace declaration only when its prefix is
    /// *visibly utilized* by this element (or listed in the InclusiveNamespaces PrefixList) and its
    /// value differs from what an ancestor already rendered.
    fn exclusive_ns_to_render(
        &self,
        e: &ElementData,
        new_scope: &BTreeMap<String, String>,
        rendered: &BTreeMap<String, String>,
        inclusive_prefixes: &[String],
    ) -> Vec<(String, String)> {
        // Visibly-utilized prefixes: the element's own prefix + every prefixed attribute's prefix.
        let mut visible: HashSet<String> = HashSet::new();
        visible.insert(e.prefix.clone().unwrap_or_default());
        for a in &e.attrs {
            if let Some(p) = &a.prefix {
                visible.insert(p.clone());
            }
        }
        // PrefixList entries are treated as visibly utilized (`#default` -> the default namespace).
        for p in inclusive_prefixes {
            if p == "#default" {
                visible.insert(String::new());
            } else {
                visible.insert(p.clone());
            }
        }

        let mut out = Vec::new();
        for pfx in &visible {
            if pfx == "xml" {
                // The predefined xml namespace is only rendered when actually used and not already
                // output; it is implicitly in scope with its fixed URI.
                let uri = new_scope
                    .get("xml")
                    .map(String::as_str)
                    .unwrap_or(XML_NS_URI);
                if rendered.get("xml").map(String::as_str) != Some(uri) {
                    out.push(("xml".to_string(), uri.to_string()));
                }
                continue;
            }
            match new_scope.get(pfx) {
                Some(uri) if !uri.is_empty() => {
                    if rendered.get(pfx).map(String::as_str) != Some(uri.as_str()) {
                        out.push((pfx.clone(), uri.clone()));
                    }
                }
                _ => {
                    // No namespace in scope for this prefix. For the default namespace, emit
                    // `xmlns=""` to undeclare only if an ancestor rendered a non-empty default.
                    if pfx.is_empty()
                        && let Some(prev) = rendered.get("")
                        && !prev.is_empty()
                    {
                        out.push((String::new(), String::new()));
                    }
                }
            }
        }
        out
    }
}

/// Inclusive-c14n namespace rendering: render every in-scope namespace whose value differs from
/// what an ancestor already rendered (so the apex of a subtree renders all inherited namespaces).
fn inclusive_ns_to_render(
    new_scope: &BTreeMap<String, String>,
    rendered: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (pfx, uri) in new_scope {
        if pfx.is_empty() && uri.is_empty() {
            // Default undeclaration: emit `xmlns=""` only to cancel an inherited non-empty default.
            if let Some(prev) = rendered.get("")
                && !prev.is_empty()
            {
                out.push((String::new(), String::new()));
            }
            continue;
        }
        if rendered.get(pfx).map(String::as_str) != Some(uri.as_str()) {
            out.push((pfx.clone(), uri.clone()));
        }
    }
    out
}

fn attr_ns_uri(a: &AttrData, scope: &BTreeMap<String, String>) -> String {
    match &a.prefix {
        None => String::new(),
        Some(p) if p == "xml" => XML_NS_URI.to_string(),
        Some(p) => scope.get(p).cloned().unwrap_or_default(),
    }
}

fn qualified_name(prefix: &Option<String>, local: &str) -> String {
    match prefix {
        Some(p) => format!("{p}:{local}"),
        None => local.to_string(),
    }
}

fn emit_pi(target: &str, data: &str, out: &mut String) {
    out.push_str("<?");
    out.push_str(target);
    if !data.is_empty() {
        out.push(' ');
        out.push_str(data);
    }
    out.push_str("?>");
}

/// C14N text-node escaping: `&`, `<`, `>` and a literal CR (`&#xD;`). Tabs and newlines are output
/// verbatim.
fn escape_text(s: &str, out: &mut String) {
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

/// C14N attribute-value escaping: `&`, `<`, `"`, and the whitespace control characters. `>` is left
/// verbatim in attribute values (per the REC).
fn escape_attr(s: &str, out: &mut String) {
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}
