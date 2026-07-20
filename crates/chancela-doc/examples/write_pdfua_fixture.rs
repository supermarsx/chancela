//! Emit the deterministic, fully tagged fixture used by the external PDF/A-2u and PDF/UA-1 gate.

use std::path::PathBuf;

use chancela_core::{Block, DocumentModel, KvRow, Run, SignatureSlot, VoteRow};

fn fixture() -> DocumentModel {
    let mut document = DocumentModel::new(
        "Ata da Assembleia Geral",
        "Encosto Estratégico Lda",
        "Deliberação sobre contas e distribuição de resultados",
    );
    document.entity_nipc = Some("500123456".to_owned());
    document.created_at = Some("2026-07-06T10:30:00Z".to_owned());
    document.blocks = vec![
        Block::Heading {
            level: 1,
            text: "Ata número três".to_owned(),
        },
        Block::Paragraph {
            runs: vec![
                Run {
                    text: "Aos seis dias do mês de julho reuniu a assembleia geral, com a presença de "
                        .to_owned(),
                    bold: false,
                    italic: false,
                },
                Run {
                    text: "todos os sócios".to_owned(),
                    bold: true,
                    italic: false,
                },
                Run {
                    text: ", para deliberar sobre a ordem de trabalhos.".to_owned(),
                    bold: false,
                    italic: true,
                },
            ],
        },
        Block::KeyValue {
            rows: vec![
                KvRow {
                    key: "Presidente da mesa".to_owned(),
                    value: "Amélia Marques".to_owned(),
                },
                KvRow {
                    key: "Data".to_owned(),
                    value: "6 de julho de 2026".to_owned(),
                },
            ],
        },
        Block::Heading {
            level: 2,
            text: "Votação".to_owned(),
        },
        Block::VoteTable {
            rows: vec![VoteRow {
                label: "Aprovação das contas".to_owned(),
                favor: 3,
                against: 0,
                abstain: 1,
            }],
        },
        Block::Rule,
        Block::SignatureBlock {
            slots: vec![SignatureSlot {
                role: "Presidente da mesa".to_owned(),
                name: "Amélia Marques".to_owned(),
            }],
        },
    ];
    document
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: write_pdfua_fixture <output.pdf>")?;
    // `pdfa::write` runs the crate's structural PDF/A/PDF/UA self-check before returning.
    let bytes = chancela_doc::pdfa::write(&fixture())?;
    std::fs::write(&output, bytes)?;
    println!("{}", output.display());
    Ok(())
}
