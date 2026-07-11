//! Exclusive XML Canonicalization (excl-c14n, W3C REC) + inclusive c14n1.1.
//!
//! This is the single highest-risk deliverable of the crate: it is implemented over `roxmltree`
//! and gated on a committed reference-vector suite (Apache Santuario / xmlsec vectors) before any
//! XAdES level machinery is trusted. See `.orchestration/plans/t67.md` §0.2.
//!
//! **Status:** skeleton (t67-e0). Filled by t67-e2.
