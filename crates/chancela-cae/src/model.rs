//! Classification model (§2.1): one node of the CAE hierarchy, tagged with its level and revision.

use serde::{Deserialize, Serialize};

/// A level of the CAE hierarchy. Serializes as the bare variant name (`"Seccao"`, `"Divisao"`, …).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CaeLevel {
    Seccao,
    Divisao,
    Grupo,
    Classe,
    Subclasse,
}

impl CaeLevel {
    /// The level implied by a code's shape: a single letter is a secção, otherwise the digit count
    /// selects the level (2→divisão … 5→subclasse). Returns `None` for a code of no valid shape.
    pub fn from_code(code: &str) -> Option<Self> {
        if code.len() == 1 && code.chars().all(|c| c.is_ascii_alphabetic()) {
            return Some(CaeLevel::Seccao);
        }
        if !code.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        match code.len() {
            2 => Some(CaeLevel::Divisao),
            3 => Some(CaeLevel::Grupo),
            4 => Some(CaeLevel::Classe),
            5 => Some(CaeLevel::Subclasse),
            _ => None,
        }
    }
}

/// A CAE revision. Serializes as `"Rev3"` / `"Rev4"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CaeRevision {
    Rev3,
    Rev4,
}

/// One classification node. `code` is the canonical printed form: secção letters ("A".."V"),
/// else the digit code ("68", "681", "6810", "68100"). `parent` is the parent code in the SAME
/// revision (None for a secção). Designations are the official Portuguese text, verbatim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaeEntry {
    pub code: String,
    pub designation: String,
    pub level: CaeLevel,
    pub revision: CaeRevision,
    pub parent: Option<String>,
}
