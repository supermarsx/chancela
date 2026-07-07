//! `gen_cae` — validate + report a CAE dataset through the crate's own integrity path.
//!
//! The embedded `data/cae_rev{3,4}.json` are produced from the vendored official DR PDFs by the
//! committed, reproducible generator `data/source/gen_cae.py` (coordinate-based PDF table
//! extraction requires a PDF engine, so the transform lives in Python; see `data/source/PROVENANCE.md`).
//! This Rust binary is the pure-cargo verification/inspection entry point: it loads a dataset —
//! the embedded one by default, or a file passed as the first argument — validates it exactly as
//! the runtime does ([`CaeCatalog::from_dataset`]), and prints the per-revision structural counts
//! and digest. It exits non-zero if validation fails, so it doubles as a regeneration guard.
//!
//! ```text
//! cargo run -p chancela-cae --bin gen_cae                 # verify the embedded dataset
//! cargo run -p chancela-cae --bin gen_cae -- some.json    # verify a candidate dataset file
//! ```

use std::process::ExitCode;

use chancela_cae::{CaeCatalog, CaeDataset, CaeMetadata};

fn main() -> ExitCode {
    let arg = std::env::args().nth(1);
    let result = match &arg {
        Some(path) => match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<CaeDataset>(&bytes) {
                Ok(ds) => CaeCatalog::from_dataset(ds).map(|c| (c, path.as_str())),
                Err(e) => {
                    eprintln!("gen_cae: {path}: parse error: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                eprintln!("gen_cae: {path}: read error: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => Ok((CaeCatalog::embedded().clone(), "<embedded>")),
    };

    match result {
        Ok((catalog, label)) => {
            report(label, catalog.metadata());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("gen_cae: integrity failure: {e}");
            ExitCode::FAILURE
        }
    }
}

fn report(label: &str, md: &CaeMetadata) {
    let c = &md.counts;
    println!("CAE dataset: {label}");
    println!("  schema_version : {}", md.schema_version);
    println!("  generated_at   : {}", md.generated_at);
    println!("  digest         : {}", md.digest);
    println!(
        "  Rev.3          : {} secções · {} divisões · {} grupos · {} classes · {} subclasses = {}",
        c.rev3.seccao,
        c.rev3.divisao,
        c.rev3.grupo,
        c.rev3.classe,
        c.rev3.subclasse,
        c.rev3.total()
    );
    println!(
        "  Rev.4          : {} secções · {} divisões · {} grupos · {} classes · {} subclasses = {}",
        c.rev4.seccao,
        c.rev4.divisao,
        c.rev4.grupo,
        c.rev4.classe,
        c.rev4.subclasse,
        c.rev4.total()
    );
}
