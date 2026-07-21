//! The PDF/PAdES validation report, lowered to a [`DocumentModel`] for PDF/A-2u rendering.
//!
//! # Why this exists as a document at all
//!
//! An operator who validates a signature may need to hand the result to somebody else — a
//! counterparty, a client, a court. The web UI can print its own screen, but a browser print
//! is a screenshot of an application: its fidelity depends on the engine and it is not an
//! artifact the product vouches for. This module produces the same report through the same
//! writer that emits every other document Chancela issues (`chancela_doc::pdfa::write`), so
//! it is a real PDF/A-2u with the font/ICC/tagging self-check applied.
//!
//! # The integrity rule that shapes the whole module
//!
//! **The report is rendered only from a validation this process just performed.** The caller
//! re-submits the PDF bytes and the server re-runs the validator; nothing here ever renders a
//! report body supplied by a client. That is not a stylistic preference. A PDF/A carrying
//! Chancela's name and layout reads to a third party as Chancela's own assertion, so an
//! endpoint that rendered client-supplied findings would let anyone produce a document
//! stating "Conforme" over a file that never validated. That is a forgery surface, and it is
//! the reason `POST /v1/signature/pdf/validate/report` takes a PDF rather than a report.
//!
//! The no-persistence invariant of the validator is untouched: this path stores nothing
//! either, it renders in memory and streams the bytes back.
//!
//! # Why label/value pairs rather than the three-column table the screen shows
//!
//! [`Block`] is the frozen document seam (§3.1) and has no general table primitive —
//! `KeyValue` is two columns and `VoteTable` is a fixed vote-tally shape. Appending a table
//! variant would fan out into the layouter, the exhaustive matches in `chancela-doc`'s
//! accessibility/tagging pass, and every working-copy exporter — a large change to the model
//! that produces sealed atas, taken on for a report's presentation. So the report degrades
//! the way `arquivo.rs` does: `Heading{level:3}` per group, `KeyValue` for the checks,
//! `Rule` between them. The verdict rides at the front of each value.
//!
//! # Verdicts are words, never colour
//!
//! Four states — `Conforme` / `Falha` / `Inconclusivo` / `Informativo` — matching the
//! on-screen table exactly, so the two renderings of the same report cannot disagree.
//! `Informativo` is load-bearing: a version string, a digest or a marker count is a measured
//! fact, not a pass. So are the claim fields (`legal_ltv_claimed`, `qualified_status_claimed`,
//! `legal_validity_claimed`, live TSL and AMA) — this tool reports local technical evidence
//! only, so `false` there is the intended answer and must never read as a failure. Absent
//! evidence is `Inconclusivo`, not `Falha`: a B-B signature legitimately carries no timestamp.
//!
//! # What the document must never claim
//!
//! No seal, no signature block, no issuing authority, no "certificamos". The document
//! reproduces the validator's own `legal_notice` verbatim and states plainly that it is a
//! machine-generated technical report which does not attest to the legal validity of the
//! signature. A PDF/A looks authoritative whether or not it is; that paragraph is the
//! correction, and a test asserts it is present.

use chancela_core::{Block, DocumentModel, KvRow, Run};

use crate::pdf_signature_validation::{
    DocTimeStampValidationReport, LocalTechnicalRenewalPlanReport, PdfSignatureValidationResponse,
    PdfValidationStatus,
};

/// The verdict vocabulary, identical to the web table's. Rendered as text only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Inconclusive,
    Info,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "Conforme",
            Self::Fail => "Falha",
            Self::Inconclusive => "Inconclusivo",
            Self::Info => "Informativo",
        }
    }
}

/// A boolean the specification requires to be true: `false` is a real non-conformity.
fn conformance(value: bool) -> Verdict {
    if value { Verdict::Pass } else { Verdict::Fail }
}

/// A boolean recording whether evidence exists. Absent evidence is not a failure.
fn presence(value: bool) -> Verdict {
    if value {
        Verdict::Pass
    } else {
        Verdict::Inconclusive
    }
}

/// Map a backend status token onto a verdict, mirroring the web's `statusVerdict`.
fn status_verdict(status: &str) -> Verdict {
    match status {
        "valid" | "passed" | "ok" | "complete" | "present" => Verdict::Pass,
        "invalid" | "failed" | "broken" => Verdict::Fail,
        "indeterminate" | "unknown" | "incomplete" | "available" | "partial" => {
            Verdict::Inconclusive
        }
        _ => Verdict::Info,
    }
}

fn overall_status_label(status: PdfValidationStatus) -> &'static str {
    match status {
        PdfValidationStatus::Unsigned => "Sem assinatura",
        PdfValidationStatus::Valid => "Válido",
        PdfValidationStatus::Invalid => "Inválido",
        PdfValidationStatus::Indeterminate => "Indeterminado",
    }
}

fn overall_status_verdict(status: PdfValidationStatus) -> Verdict {
    match status {
        PdfValidationStatus::Valid => Verdict::Pass,
        PdfValidationStatus::Invalid => Verdict::Fail,
        PdfValidationStatus::Indeterminate => Verdict::Inconclusive,
        PdfValidationStatus::Unsigned => Verdict::Info,
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "sim" } else { "não" }
}

fn kv(key: impl Into<String>, value: impl Into<String>) -> KvRow {
    KvRow {
        key: key.into(),
        value: value.into(),
    }
}

/// A check row: the verdict word leads the value, because the two-column form has no verdict
/// column and the verdict must not depend on position or colour to be read.
fn check(key: impl Into<String>, verdict: Verdict, evidence: impl Into<String>) -> KvRow {
    kv(key, format!("{} · {}", verdict.label(), evidence.into()))
}

fn plain(text: impl Into<String>) -> Block {
    Block::Paragraph {
        runs: vec![Run {
            text: text.into(),
            bold: false,
            italic: false,
        }],
    }
}

fn emphatic(text: impl Into<String>) -> Block {
    Block::Paragraph {
        runs: vec![Run {
            text: text.into(),
            bold: true,
            italic: false,
        }],
    }
}

fn group(blocks: &mut Vec<Block>, title: &str, rows: Vec<KvRow>) {
    blocks.push(Block::Heading {
        level: 3,
        text: title.to_owned(),
    });
    blocks.push(Block::KeyValue { rows });
}

/// The exact sentence that keeps the artifact honest. Asserted by a test.
pub const REPORT_DISCLAIMER: &str = "Este documento é um relatório técnico gerado automaticamente \
     a partir de uma verificação local executada pelo servidor Chancela. Não é um certificado, \
     não constitui uma declaração de autoridade, não está assinado nem selado, e não atesta a \
     validade legal da assinatura nem a qualificação do prestador.";

/// Everything the caller must supply that is not in the validation result itself.
pub struct ValidationReportContext<'a> {
    /// RFC 3339 instant at which the server ran this verification.
    pub generated_at: &'a str,
    /// The Chancela instance that produced the report (organisation name, or "Chancela").
    pub instance_name: &'a str,
    /// The server build, so a report can be tied to the code that produced it.
    pub app_version: &'a str,
}

/// Lower a validation result into the document tree. Pure: no clock, no I/O, so the same
/// result and context always produce the same bytes.
pub fn build_pdf_validation_report_document(
    report: &PdfSignatureValidationResponse,
    ctx: &ValidationReportContext<'_>,
) -> DocumentModel {
    let filename = report.filename.as_deref().unwrap_or("PDF sem nome");
    let mut blocks: Vec<Block> = Vec::new();

    // --- Provenance ------------------------------------------------------------------
    // The four facts that make the verdicts below mean anything once this leaves the app:
    // which document, which bytes, when, and which build.
    blocks.push(Block::Heading {
        level: 2,
        text: "Proveniência".to_owned(),
    });
    let declared_matches = report
        .declared_sha256
        .as_ref()
        .is_none_or(|d| *d == report.sha256)
        && report
            .declared_size_bytes
            .is_none_or(|d| d == report.size_bytes);
    let declared_present = report.declared_sha256.is_some() || report.declared_size_bytes.is_some();
    blocks.push(Block::KeyValue {
        rows: vec![
            kv("Documento verificado", filename),
            // Unabbreviated: on paper there is nothing to hover, and a truncated digest
            // identifies nothing.
            kv("SHA-256 do documento", &report.sha256),
            kv("Dimensão", format!("{} bytes", report.size_bytes)),
            kv(
                "SHA-256 declarado",
                report.declared_sha256.as_deref().unwrap_or("—"),
            ),
            kv(
                "Dimensão declarada",
                report
                    .declared_size_bytes
                    .map(|b| format!("{b} bytes"))
                    .unwrap_or_else(|| "—".to_owned()),
            ),
            kv("Verificação executada em", ctx.generated_at),
            kv("Versão do servidor", ctx.app_version),
            kv("Instância", ctx.instance_name),
            kv("Âmbito da verificação", report.scope),
            kv("Tipo de relatório", report.report_kind),
        ],
    });

    // --- What this document does and does not say -------------------------------------
    // The validator's own caveat first, verbatim: the document claims exactly what the API
    // claims. Then the statement that the sheet itself is not an act of authority.
    blocks.push(plain(report.legal_notice));
    blocks.push(emphatic(REPORT_DISCLAIMER));
    blocks.push(Block::Rule);

    // --- Overall result ---------------------------------------------------------------
    blocks.push(Block::Heading {
        level: 2,
        text: "Resultado".to_owned(),
    });
    blocks.push(Block::KeyValue {
        rows: vec![check(
            "Estado da validação",
            overall_status_verdict(report.status),
            overall_status_label(report.status),
        )],
    });

    blocks.push(Block::Heading {
        level: 2,
        text: "Verificações".to_owned(),
    });

    // --- Integrity of the submitted bytes ---------------------------------------------
    let mut integrity = vec![check(
        "Correspondência com o declarado",
        if declared_present {
            conformance(declared_matches)
        } else {
            Verdict::Inconclusive
        },
        yes_no(declared_matches),
    )];
    if declared_present && !declared_matches {
        integrity.push(kv(
            "Nota",
            "Os bytes recebidos não correspondem ao tamanho ou ao SHA-256 declarados pelo cliente.",
        ));
    }
    group(&mut blocks, "Ficheiro", integrity);
    blocks.push(Block::Rule);

    // --- Structure --------------------------------------------------------------------
    let s = &report.structure;
    group(
        &mut blocks,
        "Estrutura",
        vec![
            check("É um PDF", conformance(s.is_pdf), yes_no(s.is_pdf)),
            check("Versão", Verdict::Info, s.version.as_deref().unwrap_or("—")),
            check(
                "Deslocamento do cabeçalho",
                Verdict::Info,
                s.header_offset
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "—".to_owned()),
            ),
            check(
                "Marcador %%EOF",
                conformance(s.has_eof_marker),
                yes_no(s.has_eof_marker),
            ),
            check(
                "Marcador startxref",
                conformance(s.has_startxref),
                yes_no(s.has_startxref),
            ),
        ],
    );
    blocks.push(Block::Rule);

    // --- Signature --------------------------------------------------------------------
    let sig = &report.signature;
    let mut sig_rows = vec![check(
        "Validação executada",
        presence(sig.validation_performed),
        yes_no(sig.validation_performed),
    )];
    if let Some(err) = &sig.validation_error {
        // The parser's own error is the single most useful line in the report when set.
        sig_rows.push(kv("Erro de validação", err));
    }
    sig_rows.extend([
        check(
            "Perfil PAdES",
            Verdict::Info,
            sig.pades_profile.unwrap_or("—"),
        ),
        check(
            "Marcadores de assinatura",
            Verdict::Info,
            sig.signature_marker_count.to_string(),
        ),
        check(
            "Marcadores ByteRange",
            Verdict::Info,
            sig.byte_range_marker_count.to_string(),
        ),
        check(
            "Marcador Contents",
            conformance(sig.has_contents_marker),
            yes_no(sig.has_contents_marker),
        ),
        check(
            "Selo temporal da assinatura",
            presence(sig.timestamp.signature_timestamp_present),
            yes_no(sig.timestamp.signature_timestamp_present),
        ),
    ]);
    group(&mut blocks, "Assinatura", sig_rows);
    blocks.push(Block::Rule);

    // --- Byte range -------------------------------------------------------------------
    if let Some(br) = &sig.byte_range {
        group(
            &mut blocks,
            "Cobertura (ByteRange)",
            vec![
                check(
                    "ByteRange",
                    Verdict::Info,
                    br.byte_range
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                check(
                    "Bytes cobertos",
                    Verdict::Info,
                    format!("{} de {}", br.covered_len, br.total_len),
                ),
                check(
                    "Cobre todo o ficheiro exceto Contents",
                    conformance(br.covers_whole_file_except_contents),
                    yes_no(br.covers_whole_file_except_contents),
                ),
                check(
                    "Cobre a revisão assinada exceto Contents",
                    conformance(br.covers_signed_revision_except_contents),
                    yes_no(br.covers_signed_revision_except_contents),
                ),
                // Incremental updates after a signature are legal in PAdES: reporting them
                // as a failure would cry wolf on every correctly counter-signed document.
                check(
                    "Atualizações incrementais posteriores",
                    Verdict::Info,
                    yes_no(br.has_later_incremental_updates),
                ),
                check(
                    "Dimensão da revisão assinada",
                    Verdict::Info,
                    br.signed_revision_len.to_string(),
                ),
                check(
                    "SHA-256 da revisão assinada",
                    Verdict::Info,
                    br.digest_sha256.as_deref().unwrap_or("—"),
                ),
            ],
        );
        blocks.push(Block::Rule);
    }

    // --- CAdES ------------------------------------------------------------------------
    if let Some(cades) = &sig.cades {
        group(
            &mut blocks,
            "CAdES",
            vec![
                check("Estado", status_verdict(cades.status), cades.status),
                check(
                    "SigningCertificateV2 presente",
                    conformance(cades.signing_certificate_v2_present),
                    yes_no(cades.signing_certificate_v2_present),
                ),
                check(
                    "Sujeito do certificado",
                    Verdict::Info,
                    cades.signer_cert_subject.as_deref().unwrap_or("—"),
                ),
                check(
                    "SHA-256 do certificado",
                    Verdict::Info,
                    &cades.signer_cert_sha256,
                ),
                check(
                    "Data de assinatura declarada",
                    Verdict::Info,
                    cades.signing_time.as_deref().unwrap_or("—"),
                ),
            ],
        );
        blocks.push(Block::Rule);
    }

    // --- DSS --------------------------------------------------------------------------
    let dss = &sig.dss;
    group(
        &mut blocks,
        "DSS (evidência de revogação embebida)",
        vec![
            check("DSS presente", presence(dss.present), yes_no(dss.present)),
            check("Entradas VRI", Verdict::Info, dss.vri_count.to_string()),
            check(
                "Certificados",
                Verdict::Info,
                dss.certificate_count.to_string(),
            ),
            check("Respostas OCSP", Verdict::Info, dss.ocsp_count.to_string()),
            check("CRL", Verdict::Info, dss.crl_count.to_string()),
            check(
                "Evidência de revogação presente",
                presence(dss.revocation_evidence_present),
                yes_no(dss.revocation_evidence_present),
            ),
            check("Âmbito do estado", Verdict::Info, dss.status_scope),
        ],
    );
    blocks.push(Block::Rule);

    // --- DocTimeStamp -----------------------------------------------------------------
    let dts = &sig.doc_timestamp;
    group(
        &mut blocks,
        "DocTimeStamp",
        vec![
            check("Presente", presence(dts.present), yes_no(dts.present)),
            check("Quantidade", Verdict::Info, dts.count.to_string()),
            check("Tokens", Verdict::Info, dts.token_count.to_string()),
            check(
                "Impressões válidas",
                if dts.present {
                    conformance(dts.all_imprints_valid)
                } else {
                    Verdict::Inconclusive
                },
                yes_no(dts.all_imprints_valid),
            ),
            check("Âmbito do estado", Verdict::Info, dts.status_scope),
        ],
    );
    blocks.push(Block::Rule);

    for validation in &dts.validations {
        group(
            &mut blocks,
            &format!(
                "DocTimeStamp {} · {}",
                validation.index, validation.object_id
            ),
            doc_timestamp_rows(validation),
        );
        blocks.push(Block::Rule);
    }

    // --- Renewal plan -----------------------------------------------------------------
    let plan = &sig.local_technical_renewal_plan;
    let mut plan_rows = vec![check(
        "Estado do plano",
        status_verdict(plan.status),
        plan.status,
    )];
    plan_rows.extend(renewal_plan_rows(plan));
    group(&mut blocks, "Plano técnico local de renovação", plan_rows);
    blocks.push(plain(plan.notice));
    blocks.push(Block::Rule);

    // --- Per-signature ----------------------------------------------------------------
    let multi = &sig.multi_signature_local_renewal_plan;
    group(
        &mut blocks,
        "Assinaturas do documento",
        vec![
            check(
                "Estado do plano",
                status_verdict(multi.status),
                multi.status,
            ),
            check(
                "Número de assinaturas",
                Verdict::Info,
                multi.signature_count.to_string(),
            ),
            check(
                "Assinaturas com lacunas de evidência",
                if multi.signatures_with_local_evidence_gaps.is_empty() {
                    Verdict::Pass
                } else {
                    Verdict::Inconclusive
                },
                if multi.signatures_with_local_evidence_gaps.is_empty() {
                    "nenhuma".to_owned()
                } else {
                    multi
                        .signatures_with_local_evidence_gaps
                        .iter()
                        .map(|i| i.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                },
            ),
            check("Ação seguinte", Verdict::Info, multi.next_action),
            // Claim fields are informational by design: this tool asserts local technical
            // evidence only, so `false` is the intended answer and not a failure.
            check(
                "Perfil de longa duração reivindicado",
                Verdict::Info,
                yes_no(multi.production_long_term_profile_claimed),
            ),
            check(
                "LTV legal reivindicado",
                Verdict::Info,
                yes_no(multi.legal_ltv_claimed),
            ),
        ],
    );
    blocks.push(plain(multi.notice));
    blocks.push(Block::Rule);

    for signature in &multi.signatures {
        let sp = &signature.local_technical_renewal_plan;
        group(
            &mut blocks,
            &format!("Assinatura {} · {}", signature.index, signature.object_id),
            vec![
                check("Estado do plano", status_verdict(sp.status), sp.status),
                check(
                    "Dimensão da revisão assinada",
                    Verdict::Info,
                    signature.signed_revision_len.to_string(),
                ),
                check(
                    "Chave VRI (SHA-256)",
                    Verdict::Info,
                    &signature.vri_key_sha256,
                ),
                check(
                    "VRI no DSS",
                    presence(signature.dss_vri_present),
                    yes_no(signature.dss_vri_present),
                ),
                check(
                    "Momento de validação no VRI",
                    presence(signature.dss_vri_validation_time_present),
                    yes_no(signature.dss_vri_validation_time_present),
                ),
                check("Ação seguinte", Verdict::Info, sp.next_action),
                check(
                    "LTV legal reivindicado",
                    Verdict::Info,
                    yes_no(sp.legal_ltv_claimed),
                ),
            ],
        );
        blocks.push(Block::Rule);
    }

    // --- Trust / revocation / qualification -------------------------------------------
    let trust = &report.trust;
    let rev = &report.revocation;
    let qual = &report.qualification;
    group(
        &mut blocks,
        "Confiança, revogação e qualificação",
        vec![
            check("Confiança", status_verdict(trust.status), trust.status),
            kv("Nota", trust.message),
            check(
                "Validação de confiança executada",
                presence(trust.performed),
                yes_no(trust.performed),
            ),
            // Live TSL and AMA lookups are deliberately out of scope for the local
            // validator, so their `false` is a statement of scope, not a failed check.
            check(
                "Validação em Trusted List em direto",
                Verdict::Info,
                yes_no(trust.live_trusted_list_validation_performed),
            ),
            check(
                "Integração AMA",
                Verdict::Info,
                yes_no(trust.ama_integration_performed),
            ),
            check("Revogação", status_verdict(rev.status), rev.status),
            kv("Nota", rev.message),
            check(
                "Consulta de revogação em direto",
                Verdict::Info,
                yes_no(rev.live_fetch_performed),
            ),
            check(
                "Evidência de revogação embebida",
                presence(rev.embedded_revocation_evidence_present),
                yes_no(rev.embedded_revocation_evidence_present),
            ),
            check("Qualificação", status_verdict(qual.status), qual.status),
            kv("Nota", qual.message),
            check(
                "Estado qualificado reivindicado",
                Verdict::Info,
                yes_no(qual.qualified_status_claimed),
            ),
            check(
                "Validade legal reivindicada",
                Verdict::Info,
                yes_no(qual.legal_validity_claimed),
            ),
            check(
                "Efeito legal avaliado",
                Verdict::Info,
                yes_no(qual.legal_effect_assessed),
            ),
        ],
    );
    blocks.push(Block::Rule);

    // --- Findings ---------------------------------------------------------------------
    let findings = if report.findings.is_empty() {
        vec![check(
            "Ocorrências",
            Verdict::Pass,
            "nenhuma ocorrência registada",
        )]
    } else {
        report
            .findings
            .iter()
            .map(|f| {
                let verdict = match f.severity {
                    "error" => Verdict::Fail,
                    "warning" => Verdict::Inconclusive,
                    _ => Verdict::Info,
                };
                check(f.code, verdict, format!("{} — {}", f.severity, f.message))
            })
            .collect()
    };
    group(&mut blocks, "Ocorrências", findings);

    DocumentModel {
        title: "Relatório de verificação de assinatura PDF".to_owned(),
        // There is no legal person behind a verification report; the instance that ran the
        // check is the honest occupant of this field.
        entity_name: ctx.instance_name.to_owned(),
        entity_nipc: None,
        subject: format!("Verificação técnica local de {filename}"),
        language: "pt-PT".to_owned(),
        created_at: Some(ctx.generated_at.to_owned()),
        blocks,
    }
}

fn doc_timestamp_rows(v: &DocTimeStampValidationReport) -> Vec<KvRow> {
    let mut rows = vec![check("Estado", status_verdict(v.status), v.status)];
    if let Some(reason) = v.failure_reason {
        rows.push(kv("Motivo de falha", reason));
    }
    rows.extend([
        check(
            "ByteRange",
            Verdict::Info,
            v.byte_range
                .map(|b| {
                    b.iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "—".to_owned()),
        ),
        check(
            "SHA-256 do documento",
            Verdict::Info,
            v.document_digest_sha256.as_deref().unwrap_or("—"),
        ),
        check(
            "Impressão do token",
            Verdict::Info,
            v.token_imprint_sha256.as_deref().unwrap_or("—"),
        ),
        check(
            "Algoritmo de hash",
            Verdict::Info,
            v.token_hash_algorithm.as_deref().unwrap_or("—"),
        ),
    ]);
    rows
}

fn renewal_plan_rows(plan: &LocalTechnicalRenewalPlanReport) -> Vec<KvRow> {
    vec![
        check(
            "Selo temporal da assinatura",
            presence(plan.signature_timestamp_present),
            yes_no(plan.signature_timestamp_present),
        ),
        check(
            "Evidência de revogação no DSS",
            presence(plan.dss_revocation_evidence_present),
            yes_no(plan.dss_revocation_evidence_present),
        ),
        check(
            "Momento de validação no DSS",
            presence(plan.dss_validation_time_present),
            yes_no(plan.dss_validation_time_present),
        ),
        check(
            "DocTimeStamp presente",
            presence(plan.doc_timestamp_present),
            yes_no(plan.doc_timestamp_present),
        ),
        check(
            "Impressões do DocTimeStamp válidas",
            if plan.doc_timestamp_present {
                conformance(plan.doc_timestamp_imprints_valid)
            } else {
                Verdict::Inconclusive
            },
            yes_no(plan.doc_timestamp_imprints_valid),
        ),
        check(
            "Entradas em falta",
            if plan.missing_inputs.is_empty() {
                Verdict::Pass
            } else {
                Verdict::Inconclusive
            },
            if plan.missing_inputs.is_empty() {
                "nenhuma".to_owned()
            } else {
                plan.missing_inputs.join(", ")
            },
        ),
        check("Ação seguinte", Verdict::Info, plan.next_action),
        check(
            "Lacuna de evidência local",
            if plan.has_local_evidence_gap {
                Verdict::Inconclusive
            } else {
                Verdict::Pass
            },
            yes_no(plan.has_local_evidence_gap),
        ),
        check(
            "Perfil de longa duração reivindicado",
            Verdict::Info,
            yes_no(plan.production_long_term_profile_claimed),
        ),
        check(
            "LTV legal reivindicado",
            Verdict::Info,
            yes_no(plan.legal_ltv_claimed),
        ),
    ]
}
