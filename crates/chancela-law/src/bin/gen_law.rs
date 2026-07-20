//! `gen_law` — validate + report a law corpus through the crate's own integrity/authenticity path.
//!
//! The embedded `data/law_corpus.json` is produced by the committed, reproducible generator
//! `data/source/gen_law.py` (which also documents the E1b DRE vendoring pipeline). This Rust binary
//! is the pure-cargo verification/inspection entry point: it loads a corpus — the embedded one by
//! default, or a file passed as the first argument — validates it exactly as the runtime does
//! ([`LawCatalog::from_corpus`], including the authenticity gate) and prints its counts + digest.
//! It exits non-zero on any failure, so it doubles as a regeneration guard.
//!
//! ```text
//! cargo run -p chancela-law --bin gen_law                 # verify the embedded corpus
//! cargo run -p chancela-law --bin gen_law -- some.json    # verify a candidate corpus file
//! ```

use std::process::ExitCode;

use chancela_law::{LawCatalog, LawCorpus, LawMetadata};

fn main() -> ExitCode {
    let arg = std::env::args().nth(1);
    let result = match &arg {
        Some(path) => match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<LawCorpus>(&bytes) {
                Ok(corpus) => LawCatalog::from_corpus(corpus).map(|c| (c, path.as_str())),
                Err(e) => {
                    eprintln!("gen_law: {path}: parse error: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                eprintln!("gen_law: {path}: read error: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => Ok((LawCatalog::embedded().clone(), "<embedded>")),
    };

    match result {
        Ok((catalog, label)) => {
            report(label, catalog.metadata());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("gen_law: integrity failure: {e}");
            ExitCode::FAILURE
        }
    }
}

fn report(label: &str, md: &LawMetadata) {
    let c = &md.counts;
    println!("Law corpus: {label}");
    println!("  schema_version : {}", md.schema_version);
    println!("  generated_at   : {}", md.generated_at);
    println!("  digest         : {}", md.digest);
    println!(
        "  counts         : {} diplomas · {} articles ({} verified, {} automated-review, {} pending)",
        c.diplomas, c.articles, c.verified, c.automated_review, c.pending
    );
}
