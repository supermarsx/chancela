//! The public **Simple JSON** mirror schema (plan t23 §2.3): a flat top-level array of classification
//! nodes that anyone can host and diff. Intentionally the same shape as the embedded
//! `data/cae_rev{3,4}.json` entry arrays, so producing a mirror is trivial.
//!
//! ```json
//! [
//!   {"code":"A","designation":"Agricultura, produção animal, caça, floresta e pesca.","revision":"Rev4","level":"Seccao","parent":null},
//!   {"code":"68","designation":"Atividades imobiliárias.","revision":"Rev4"},
//!   {"code":"68110","designation":"Compra e venda de bens imobiliários.","revision":"Rev4"}
//! ]
//! ```
//!
//! - **Required per node:** `code`, `designation`, `revision` (`"Rev3"` | `"Rev4"`).
//! - **Optional:** `level` (`"Seccao"`/`"Divisao"`/`"Grupo"`/`"Classe"`/`"Subclasse"`) and `parent`.
//!   When omitted they are **derived** exactly as the committed `gen_cae.py` generator does — `level`
//!   from the code shape ([`CaeLevel::from_code`]); `parent` from the code prefix (a grupo/classe/
//!   subclasse drops its last digit), and for a **divisão** from the most recent secção **in array
//!   order**. When present they are used verbatim. Either way the result runs through structural
//!   integrity + full-count fidelity, so a wrong derivation or value is rejected downstream, never
//!   silently trusted.
//!
//! **Both-revisions ruling.** A mirror is **one flat array carrying both revisions**; each node
//! self-tags via its `revision` field, and the parser partitions on it. (Per-revision hosting is
//! achieved by concatenating the two arrays — there is no separate per-revision format.) Because the
//! completeness rule requires a superseding obtain to be a complete both-revision dataset, a
//! single-revision array leaves the other revision empty and simply fails the fidelity gate.
//!
//! Derived-`parent` mirrors therefore MUST be ordered so each secção precedes its divisões (the
//! generator's document order); a misordered array with omitted parents produces a wrong derivation
//! that the integrity gate rejects — it is never accepted as if correct.

use serde::Deserialize;

use crate::dataset::{CAE_SCHEMA_VERSION, CaeDataset};
use crate::error::CaeError;
use crate::model::{CaeEntry, CaeLevel, CaeRevision};

use super::now_rfc3339;

/// Human note recorded on a Simple-JSON-obtained dataset's envelope.
const SIMPLE_SOURCE_NOTE: &str = "Obtido de um espelho no formato público Simple JSON (lista plana de nós CAE). \
     Ver crates/chancela-cae/data/source/SIMPLE_JSON_SCHEMA.md.";

/// One node as it appears in a Simple-JSON mirror array. `level`/`parent` are optional and derived
/// when absent (see the module docs); `revision` self-tags each node so both revisions may share one
/// array. Unknown extra keys are ignored (forward-compatible with richer mirrors).
#[derive(Debug, Deserialize)]
struct SimpleNode {
    code: String,
    designation: String,
    revision: CaeRevision,
    #[serde(default)]
    level: Option<CaeLevel>,
    #[serde(default)]
    parent: Option<String>,
}

/// Parse Simple-JSON mirror bytes into a [`CaeDataset`], deriving any absent `level`/`parent` the
/// same way the offline generator does. Malformed JSON or a code whose level cannot be derived is a
/// [`CaeError::Parse`]; structural correctness is enforced later by the integrity + fidelity gates.
pub(super) fn parse_simple_json(bytes: &[u8]) -> Result<CaeDataset, CaeError> {
    let nodes: Vec<SimpleNode> =
        serde_json::from_slice(bytes).map_err(|e| CaeError::Parse(e.to_string()))?;

    let mut rev3: Vec<CaeEntry> = Vec::new();
    let mut rev4: Vec<CaeEntry> = Vec::new();
    // The most recent secção walked, per revision — the divisão-parent source (matches gen_cae.py).
    let mut cur_section_rev3: Option<String> = None;
    let mut cur_section_rev4: Option<String> = None;

    for node in nodes {
        let level = match node.level {
            Some(level) => level,
            None => CaeLevel::from_code(&node.code).ok_or_else(|| {
                CaeError::Parse(format!(
                    "Simple JSON: cannot derive a level for code {:?} (no valid CAE code shape)",
                    node.code
                ))
            })?,
        };

        let cur_section = match node.revision {
            CaeRevision::Rev3 => &mut cur_section_rev3,
            CaeRevision::Rev4 => &mut cur_section_rev4,
        };
        if level == CaeLevel::Seccao {
            *cur_section = Some(node.code.clone());
        }

        let parent = match node.parent {
            // An explicit parent is used verbatim (integrity still validates it).
            Some(parent) => Some(parent),
            None => derive_parent(&node.code, level, cur_section.as_deref()),
        };

        let entry = CaeEntry {
            code: node.code,
            designation: node.designation,
            level,
            revision: node.revision,
            parent,
        };
        match node.revision {
            CaeRevision::Rev3 => rev3.push(entry),
            CaeRevision::Rev4 => rev4.push(entry),
        }
    }

    Ok(CaeDataset {
        schema_version: CAE_SCHEMA_VERSION,
        generated_at: now_rfc3339(),
        source_note: SIMPLE_SOURCE_NOTE.to_owned(),
        rev3,
        rev4,
        provenance: None,
    })
}

/// Derive a node's parent code the same way `gen_cae.py` does: a secção has none; a divisão inherits
/// the most recent secção in array order; a deeper level drops its code's last digit.
fn derive_parent(code: &str, level: CaeLevel, cur_section: Option<&str>) -> Option<String> {
    match level {
        CaeLevel::Seccao => None,
        CaeLevel::Divisao => cur_section.map(str::to_owned),
        _ => code
            .get(..code.len().saturating_sub(1))
            .filter(|prefix| !prefix.is_empty())
            .map(str::to_owned),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_level_and_parent_when_absent() {
        // A minimal, correctly-ordered slice with NO level/parent keys: everything is derived.
        let json = r#"[
            {"code":"A","designation":"Agricultura.","revision":"Rev4"},
            {"code":"68","designation":"Atividades imobiliarias.","revision":"Rev4"},
            {"code":"681","designation":"Compra, venda e arrendamento.","revision":"Rev4"},
            {"code":"6811","designation":"Compra e venda.","revision":"Rev4"},
            {"code":"68110","designation":"Compra e venda de bens imobiliarios.","revision":"Rev4"}
        ]"#;
        let ds = parse_simple_json(json.as_bytes()).expect("derivable slice parses");
        assert!(ds.rev3.is_empty());
        assert_eq!(ds.rev4.len(), 5);

        let by = |code: &str| ds.rev4.iter().find(|e| e.code == code).unwrap();
        assert_eq!(by("A").level, CaeLevel::Seccao);
        assert_eq!(by("A").parent, None);
        // Divisão inherits the most recent secção in array order.
        assert_eq!(by("68").level, CaeLevel::Divisao);
        assert_eq!(by("68").parent.as_deref(), Some("A"));
        // Deeper levels drop the last code digit.
        assert_eq!(by("681").parent.as_deref(), Some("68"));
        assert_eq!(by("6811").parent.as_deref(), Some("681"));
        assert_eq!(by("68110").level, CaeLevel::Subclasse);
        assert_eq!(by("68110").parent.as_deref(), Some("6811"));
    }

    #[test]
    fn explicit_level_and_parent_are_used_verbatim() {
        let json = r#"[
            {"code":"B","designation":"Seccao B.","revision":"Rev3","level":"Seccao","parent":null},
            {"code":"05","designation":"Divisao.","revision":"Rev3","level":"Divisao","parent":"B"}
        ]"#;
        let ds = parse_simple_json(json.as_bytes()).expect("explicit slice parses");
        assert_eq!(ds.rev3.len(), 2);
        assert_eq!(ds.rev3[1].parent.as_deref(), Some("B"));
    }

    #[test]
    fn both_revisions_partition_by_tag() {
        let json = br#"[
            {"code":"A","designation":"Sec A r4.","revision":"Rev4"},
            {"code":"A","designation":"Sec A r3.","revision":"Rev3"}
        ]"#;
        let ds = parse_simple_json(json).expect("mixed-revision array parses");
        assert_eq!(ds.rev3.len(), 1);
        assert_eq!(ds.rev4.len(), 1);
        assert_eq!(ds.rev3[0].designation, "Sec A r3.");
        assert_eq!(ds.rev4[0].designation, "Sec A r4.");
    }

    #[test]
    fn undecodable_code_shape_is_a_parse_error() {
        let json = br#"[{"code":"XYZ","designation":"bad.","revision":"Rev4"}]"#;
        let err = parse_simple_json(json).expect_err("no derivable level");
        assert!(matches!(err, CaeError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        let err = parse_simple_json(b"[{ not json").expect_err("malformed");
        assert!(matches!(err, CaeError::Parse(_)), "got {err:?}");
    }
}
