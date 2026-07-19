//! Validate PDF files **from disk** against the structural PDF/A-2u + PDF/UA-1 invariants that
//! [`chancela_doc::selfcheck`] asserts — a JVM-free loop over files the write-time gate cannot see.
//!
//! # What this certifies
//!
//! This checks **files produced by this writer**, and says so. It is not a general ISO 19005
//! validator and must not be described as one: several of its rules compare against Chancela's own
//! bounded shape — the ICC profile we ship, the writer's structure roles, a closed content-operator
//! list — so it will reject conformant third-party PDFs by design. What it certifies for our own
//! files is documented rule by rule in `selfcheck`'s module docs, together with the residual gaps.
//!
//! # Why it exists
//!
//! `pdfa::write` verifies the bytes it is about to return, so it structurally cannot see:
//!
//!   1. **Signed output.** `chancela-pades` appends an incremental update after `pdfa::write` has
//!      returned. The signed file is the one Chancela actually ships, and until this example
//!      existed nothing re-validated it — which is how a signed file came to be shipping without
//!      the `/ID` in its file trailer that ISO 19005-2 6.1.3 requires.
//!   2. **Archived / round-tripped bytes.** Anything read back from storage rather than freshly
//!      produced in-process.
//!
//! Signed and unsigned files are told apart by the catalog's `/AcroForm` and checked under the
//! matching profile, so a signed file is held to the signature rules and an unsigned one to the
//! rule that it has no signature machinery at all.
//!
//! Usage: `check_pdfa <path>...` — one line per file, non-zero exit if any file fails.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chancela_doc::selfcheck::{self, UaClaim};

fn main() -> ExitCode {
    let paths: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    if paths.is_empty() {
        eprintln!("usage: check_pdfa <path>...");
        return ExitCode::FAILURE;
    }

    let mut failed = 0usize;
    for path in &paths {
        let problems = check(path);
        if problems.is_empty() {
            println!("ok    {}", path.display());
        } else {
            failed += 1;
            println!("FAIL  {}", path.display());
            for problem in problems {
                println!("        {problem}");
            }
        }
    }

    let total = paths.len();
    if failed == 0 {
        eprintln!("{total} file(s) satisfy the structural PDF/A-2u + PDF/UA-1 invariants");
        eprintln!(
            "note: structural self-check over files produced by this writer — not a general \
             ISO 19005 conformance certificate"
        );
        ExitCode::SUCCESS
    } else {
        eprintln!("{failed} of {total} file(s) FAILED the structural self-check");
        ExitCode::FAILURE
    }
}

/// Every problem found in `path`, so one run reports all of them rather than only the first.
///
/// PDF/A-2U conformance and the PDF/UA-1 claim are asked separately: a file can be perfectly
/// archivable while claiming an accessibility conformance it does not have, and collapsing the two
/// would hide whichever came second.
fn check(path: &Path) -> Vec<String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => return vec![format!("cannot read: {e}")],
    };

    let mut problems = Vec::new();
    if let Err(e) = selfcheck::verify_any(&bytes) {
        problems.push(format!("PDF/A-2U: {e}"));
    }
    match selfcheck::ua_claim(&bytes) {
        Ok(UaClaim::NotClaimed | UaClaim::Claimed) => {}
        Ok(UaClaim::Falsified(reason)) => problems.push(format!("PDF/UA-1: {reason}")),
        Err(e) => problems.push(format!("PDF/UA-1: {e}")),
    }
    problems
}
