//! Local metadata consistency lint for the embedded template catalog.
//!
//! This validates structural catalog metadata and authored template bindings only. It is not legal
//! review, DRE/source authority verification, registry/provider integration, signing assurance, or
//! a claim that rendered templates have legal effect.

use std::collections::BTreeMap;
use std::fmt;

use chancela_core::{EntityFamily, LifecycleStage, MeetingChannel, SignaturePolicyHint};
use serde_json::Value;

use crate::{ASSET_FILES, BlockSpec, TemplateSpec, TemplateSpecDto, rule_pack_law_references};

const REQUIRED_TEMPLATE_METADATA_FIELDS: &[&str] = &[
    "id",
    "family",
    "stage",
    "channels",
    "signature_policy",
    "rule_pack_id",
    "locale",
    "blocks",
];

const REQUIRED_STRING_METADATA_FIELDS: &[&str] = &[
    "id",
    "family",
    "stage",
    "signature_policy",
    "rule_pack_id",
    "locale",
];

const POST_ACT_SEALED_PROVENANCE_FIELDS: &[&str] = &["ata_number", "payload_digest"];
pub const POST_ACT_SEALED_PROVENANCE_REQUIREMENT: &str =
    "post-act Certidao/Extrato templates must bind sealed-act provenance";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogMetadataIssue {
    pub asset: String,
    pub template_id: Option<String>,
    pub kind: CatalogMetadataIssueKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogMetadataIssueKind {
    MissingField(&'static str),
    BlankStringField(&'static str),
    DuplicateId {
        first_asset: String,
    },
    InvalidJson(String),
    InvalidSchema(String),
    TemplateIdFamilyMismatch {
        expected_prefix: &'static str,
    },
    RulePackFamilyMismatch {
        expected_rule_pack_id: &'static str,
        actual_rule_pack_id: String,
    },
    SignaturePolicyFamilyMismatch {
        expected_signature_policy: SignaturePolicyHint,
        actual_signature_policy: SignaturePolicyHint,
    },
    TemplateIdAssetStemMismatch {
        expected_stem: String,
        actual_stem: String,
    },
    MissingTemplateIdVersionSuffix,
    EmptyBlocks,
    TemplateStageMismatch {
        expected_stage: LifecycleStage,
        actual_stage: LifecycleStage,
    },
    DuplicateChannel {
        channel: MeetingChannel,
    },
    ChannelOrderMismatch {
        previous_channel: MeetingChannel,
        out_of_order_channel: MeetingChannel,
    },
    TemplateChannelsMismatch {
        expected_channels: Vec<MeetingChannel>,
        actual_channels: Vec<MeetingChannel>,
    },
    FamilyChannelMismatch {
        family: EntityFamily,
        channel: MeetingChannel,
    },
    MissingRulePackLawReference {
        rule_pack_id: String,
    },
    MissingTemplateLawReference {
        rule_pack_id: String,
    },
    IncompleteLawReference {
        citation: String,
        field: &'static str,
    },
    MissingSemanticBinding {
        field: &'static str,
        requirement: &'static str,
    },
}

impl fmt::Display for CatalogMetadataIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let template_id = self.template_id.as_deref().unwrap_or("<unknown>");
        match &self.kind {
            CatalogMetadataIssueKind::MissingField(field) => write!(
                f,
                "{}.json ({template_id}): missing required metadata field `{field}`",
                self.asset
            ),
            CatalogMetadataIssueKind::BlankStringField(field) => write!(
                f,
                "{}.json ({template_id}): blank required metadata field `{field}`",
                self.asset
            ),
            CatalogMetadataIssueKind::DuplicateId { first_asset } => write!(
                f,
                "{}.json ({template_id}): duplicate template id first seen in {first_asset}.json",
                self.asset
            ),
            CatalogMetadataIssueKind::InvalidJson(error) => {
                write!(f, "{}.json: invalid JSON: {error}", self.asset)
            }
            CatalogMetadataIssueKind::InvalidSchema(error) => write!(
                f,
                "{}.json ({template_id}): invalid template schema: {error}",
                self.asset
            ),
            CatalogMetadataIssueKind::TemplateIdFamilyMismatch { expected_prefix } => write!(
                f,
                "{}.json ({template_id}): template id does not use family prefix `{expected_prefix}`",
                self.asset
            ),
            CatalogMetadataIssueKind::RulePackFamilyMismatch {
                expected_rule_pack_id,
                actual_rule_pack_id,
            } => write!(
                f,
                "{}.json ({template_id}): rule_pack_id `{actual_rule_pack_id}` does not match family binding `{expected_rule_pack_id}`",
                self.asset
            ),
            CatalogMetadataIssueKind::SignaturePolicyFamilyMismatch {
                expected_signature_policy,
                actual_signature_policy,
            } => write!(
                f,
                "{}.json ({template_id}): signature_policy `{actual_signature_policy:?}` does not match family binding `{expected_signature_policy:?}`",
                self.asset
            ),
            CatalogMetadataIssueKind::TemplateIdAssetStemMismatch {
                expected_stem,
                actual_stem,
            } => write!(
                f,
                "{}.json ({template_id}): template id stem `{actual_stem}` does not match asset stem `{expected_stem}`",
                self.asset
            ),
            CatalogMetadataIssueKind::MissingTemplateIdVersionSuffix => write!(
                f,
                "{}.json ({template_id}): template id must use a `/vN` version suffix",
                self.asset
            ),
            CatalogMetadataIssueKind::EmptyBlocks => write!(
                f,
                "{}.json ({template_id}): template must author at least one block",
                self.asset
            ),
            CatalogMetadataIssueKind::TemplateStageMismatch {
                expected_stage,
                actual_stage,
            } => write!(
                f,
                "{}.json ({template_id}): stage `{actual_stage:?}` does not match id-derived stage `{expected_stage:?}`",
                self.asset
            ),
            CatalogMetadataIssueKind::DuplicateChannel { channel } => write!(
                f,
                "{}.json ({template_id}): duplicate channel `{channel:?}`",
                self.asset
            ),
            CatalogMetadataIssueKind::ChannelOrderMismatch {
                previous_channel,
                out_of_order_channel,
            } => write!(
                f,
                "{}.json ({template_id}): channel `{out_of_order_channel:?}` appears after `{previous_channel:?}` out of canonical order",
                self.asset
            ),
            CatalogMetadataIssueKind::TemplateChannelsMismatch {
                expected_channels,
                actual_channels,
            } => write!(
                f,
                "{}.json ({template_id}): channels `{actual_channels:?}` do not match id-scoped channels `{expected_channels:?}`",
                self.asset
            ),
            CatalogMetadataIssueKind::FamilyChannelMismatch { family, channel } => write!(
                f,
                "{}.json ({template_id}): channel `{channel:?}` is not allowed for template family `{family:?}`",
                self.asset
            ),
            CatalogMetadataIssueKind::MissingRulePackLawReference { rule_pack_id } => write!(
                f,
                "{}.json ({template_id}): rule_pack_id `{rule_pack_id}` has no local law-reference anchor",
                self.asset
            ),
            CatalogMetadataIssueKind::MissingTemplateLawReference { rule_pack_id } => write!(
                f,
                "{}.json ({template_id}): template derives no law_references from rule_pack_id `{rule_pack_id}` or thresholds",
                self.asset
            ),
            CatalogMetadataIssueKind::IncompleteLawReference { citation, field } => write!(
                f,
                "{}.json ({template_id}): law reference `{citation}` has blank `{field}`",
                self.asset
            ),
            CatalogMetadataIssueKind::MissingSemanticBinding { field, requirement } => write!(
                f,
                "{}.json ({template_id}): missing semantic binding `{field}` ({requirement})",
                self.asset
            ),
        }
    }
}

pub fn validate_embedded_catalog_metadata() -> Vec<CatalogMetadataIssue> {
    validate_catalog_metadata(ASSET_FILES)
}

pub fn catalog_metadata_report(issues: &[CatalogMetadataIssue]) -> String {
    issues
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn validate_catalog_metadata(assets: &[(&str, &str)]) -> Vec<CatalogMetadataIssue> {
    let mut issues = Vec::new();
    let mut seen_ids = BTreeMap::<String, String>::new();

    for (asset, json) in assets {
        let raw: Value = match serde_json::from_str(json) {
            Ok(raw) => raw,
            Err(error) => {
                issues.push(metadata_issue(
                    asset,
                    None,
                    CatalogMetadataIssueKind::InvalidJson(error.to_string()),
                ));
                continue;
            }
        };

        let Some(object) = raw.as_object() else {
            issues.push(metadata_issue(
                asset,
                None,
                CatalogMetadataIssueKind::InvalidSchema(
                    "template asset root must be a JSON object".to_string(),
                ),
            ));
            continue;
        };

        let template_id = object
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_owned);
        let mut missing_required = false;

        for &field in REQUIRED_TEMPLATE_METADATA_FIELDS {
            if !object.contains_key(field) {
                issues.push(metadata_issue(
                    asset,
                    template_id.as_deref(),
                    CatalogMetadataIssueKind::MissingField(field),
                ));
                missing_required = true;
            }
        }

        for &field in REQUIRED_STRING_METADATA_FIELDS {
            if let Some(value) = object.get(field).and_then(Value::as_str)
                && value.trim().is_empty()
            {
                issues.push(metadata_issue(
                    asset,
                    template_id.as_deref(),
                    CatalogMetadataIssueKind::BlankStringField(field),
                ));
            }
        }

        if let Some(id) = &template_id {
            if let Some(first_asset) = seen_ids.insert(id.clone(), (*asset).to_string()) {
                issues.push(metadata_issue(
                    asset,
                    Some(id),
                    CatalogMetadataIssueKind::DuplicateId { first_asset },
                ));
            }
        }

        if missing_required {
            continue;
        }

        let dto: TemplateSpecDto = match serde_json::from_value(raw) {
            Ok(dto) => dto,
            Err(error) => {
                issues.push(metadata_issue(
                    asset,
                    template_id.as_deref(),
                    CatalogMetadataIssueKind::InvalidSchema(error.to_string()),
                ));
                continue;
            }
        };
        let spec = TemplateSpec::from(dto);

        let actual_stem = template_id_stem(&spec.id);
        if actual_stem != *asset {
            issues.push(metadata_issue(
                asset,
                Some(&spec.id),
                CatalogMetadataIssueKind::TemplateIdAssetStemMismatch {
                    expected_stem: (*asset).to_string(),
                    actual_stem: actual_stem.to_string(),
                },
            ));
        }
        if !has_template_id_version_suffix(&spec.id) {
            issues.push(metadata_issue(
                asset,
                Some(&spec.id),
                CatalogMetadataIssueKind::MissingTemplateIdVersionSuffix,
            ));
        }
        if spec.blocks.is_empty() {
            issues.push(metadata_issue(
                asset,
                Some(&spec.id),
                CatalogMetadataIssueKind::EmptyBlocks,
            ));
        }

        // Local profile/catalog drift guard only. This does not verify source law text or values.
        let expected_prefix = expected_template_id_prefix_for_family(spec.family);
        if !spec.id.starts_with(expected_prefix) {
            issues.push(metadata_issue(
                asset,
                Some(&spec.id),
                CatalogMetadataIssueKind::TemplateIdFamilyMismatch { expected_prefix },
            ));
        }

        let expected_rule_pack_id = expected_rule_pack_id_for_family(spec.family);
        if spec.rule_pack_id != expected_rule_pack_id {
            issues.push(metadata_issue(
                asset,
                Some(&spec.id),
                CatalogMetadataIssueKind::RulePackFamilyMismatch {
                    expected_rule_pack_id,
                    actual_rule_pack_id: spec.rule_pack_id.clone(),
                },
            ));
        }

        let expected_signature_policy = expected_signature_policy_for_family(spec.family);
        if spec.signature_policy != expected_signature_policy {
            issues.push(metadata_issue(
                asset,
                Some(&spec.id),
                CatalogMetadataIssueKind::SignaturePolicyFamilyMismatch {
                    expected_signature_policy,
                    actual_signature_policy: spec.signature_policy,
                },
            ));
        }

        if let Some(expected_stage) = expected_stage_for_template_id(&spec.id)
            && spec.stage != expected_stage
        {
            issues.push(metadata_issue(
                asset,
                Some(&spec.id),
                CatalogMetadataIssueKind::TemplateStageMismatch {
                    expected_stage,
                    actual_stage: spec.stage,
                },
            ));
        }

        let mut seen_channels = Vec::new();
        let mut previous_channel = None;
        let allowed_channels = allowed_channels_for_template_family(spec.family);
        for channel in &spec.channels {
            if seen_channels.contains(channel) {
                issues.push(metadata_issue(
                    asset,
                    Some(&spec.id),
                    CatalogMetadataIssueKind::DuplicateChannel { channel: *channel },
                ));
            }
            if let Some(previous) = previous_channel
                && channel_order(*channel) < channel_order(previous)
            {
                issues.push(metadata_issue(
                    asset,
                    Some(&spec.id),
                    CatalogMetadataIssueKind::ChannelOrderMismatch {
                        previous_channel: previous,
                        out_of_order_channel: *channel,
                    },
                ));
            }
            seen_channels.push(*channel);
            previous_channel = Some(*channel);
            if !allowed_channels.contains(channel)
                && !is_existing_authored_channel_compatibility(&spec.id, spec.family, *channel)
            {
                issues.push(metadata_issue(
                    asset,
                    Some(&spec.id),
                    CatalogMetadataIssueKind::FamilyChannelMismatch {
                        family: spec.family,
                        channel: *channel,
                    },
                ));
            }
        }
        if let Some(expected_channels) = expected_channels_for_template_id(&spec.id)
            && spec.channels != expected_channels
        {
            issues.push(metadata_issue(
                asset,
                Some(&spec.id),
                CatalogMetadataIssueKind::TemplateChannelsMismatch {
                    expected_channels,
                    actual_channels: spec.channels.clone(),
                },
            ));
        }

        if requires_post_act_sealed_provenance(spec.stage) {
            for &field in POST_ACT_SEALED_PROVENANCE_FIELDS {
                if !block_templates_bind_field(&spec.blocks, field) {
                    issues.push(metadata_issue(
                        asset,
                        Some(&spec.id),
                        CatalogMetadataIssueKind::MissingSemanticBinding {
                            field,
                            requirement: POST_ACT_SEALED_PROVENANCE_REQUIREMENT,
                        },
                    ));
                }
            }
        }

        // Structured discovery anchors for API/template picker only. They are not source-law
        // authority, exhaustive law mapping, or legal review.
        if rule_pack_law_references(&spec.rule_pack_id).is_empty() {
            issues.push(metadata_issue(
                asset,
                Some(&spec.id),
                CatalogMetadataIssueKind::MissingRulePackLawReference {
                    rule_pack_id: spec.rule_pack_id.clone(),
                },
            ));
        }
        if spec.law_references.is_empty() {
            issues.push(metadata_issue(
                asset,
                Some(&spec.id),
                CatalogMetadataIssueKind::MissingTemplateLawReference {
                    rule_pack_id: spec.rule_pack_id.clone(),
                },
            ));
        }
        for reference in &spec.law_references {
            if reference.source_id.trim().is_empty() {
                issues.push(metadata_issue(
                    asset,
                    Some(&spec.id),
                    CatalogMetadataIssueKind::IncompleteLawReference {
                        citation: reference.citation.clone(),
                        field: "source_id",
                    },
                ));
            }
            if reference.source_label.trim().is_empty() {
                issues.push(metadata_issue(
                    asset,
                    Some(&spec.id),
                    CatalogMetadataIssueKind::IncompleteLawReference {
                        citation: reference.citation.clone(),
                        field: "source_label",
                    },
                ));
            }
            if reference.citation.trim().is_empty() {
                issues.push(metadata_issue(
                    asset,
                    Some(&spec.id),
                    CatalogMetadataIssueKind::IncompleteLawReference {
                        citation: "<blank>".to_string(),
                        field: "citation",
                    },
                ));
            }
        }
    }

    issues
}

fn metadata_issue(
    asset: &str,
    template_id: Option<&str>,
    kind: CatalogMetadataIssueKind,
) -> CatalogMetadataIssue {
    CatalogMetadataIssue {
        asset: asset.to_owned(),
        template_id: template_id.map(str::to_owned),
        kind,
    }
}

fn template_id_stem(template_id: &str) -> &str {
    template_id
        .split_once('/')
        .map(|(stem, _)| stem)
        .unwrap_or(template_id)
}

fn has_template_id_version_suffix(template_id: &str) -> bool {
    let Some((stem, version)) = template_id.rsplit_once("/v") else {
        return false;
    };
    !stem.is_empty() && !version.is_empty() && version.chars().all(|c| c.is_ascii_digit())
}

fn expected_template_id_prefix_for_family(family: EntityFamily) -> &'static str {
    match family {
        EntityFamily::CommercialCompany => "csc-",
        EntityFamily::Condominium => "condominio-",
        EntityFamily::Association => "assoc-",
        EntityFamily::Foundation => "fundacao-",
        EntityFamily::Cooperative => "cooperativa-",
    }
}

fn expected_rule_pack_id_for_family(family: EntityFamily) -> &'static str {
    match family {
        EntityFamily::CommercialCompany => "csc-art63/v2",
        EntityFamily::Condominium => "condominio-dl268/v1",
        EntityFamily::Association => "assoc-cc/v1",
        EntityFamily::Foundation => "fundacao-cc/v1",
        EntityFamily::Cooperative => "cooperativa-ccoop/v1",
    }
}

fn expected_signature_policy_for_family(family: EntityFamily) -> SignaturePolicyHint {
    match family {
        EntityFamily::CommercialCompany => SignaturePolicyHint::QualifiedPreferred,
        EntityFamily::Condominium => SignaturePolicyHint::QualifiedOrHandwritten,
        EntityFamily::Association | EntityFamily::Foundation | EntityFamily::Cooperative => {
            SignaturePolicyHint::ManualAttested
        }
    }
}

fn allowed_channels_for_template_family(family: EntityFamily) -> &'static [MeetingChannel] {
    match family {
        EntityFamily::CommercialCompany => &[
            MeetingChannel::Physical,
            MeetingChannel::Hybrid,
            MeetingChannel::Telematic,
            MeetingChannel::WrittenResolution,
        ],
        EntityFamily::Condominium => &[
            MeetingChannel::Physical,
            MeetingChannel::Hybrid,
            MeetingChannel::Telematic,
        ],
        EntityFamily::Association => &[
            MeetingChannel::Physical,
            MeetingChannel::Hybrid,
            MeetingChannel::Telematic,
            MeetingChannel::WrittenResolution,
        ],
        EntityFamily::Foundation => &[
            MeetingChannel::Physical,
            MeetingChannel::Hybrid,
            MeetingChannel::Telematic,
        ],
        EntityFamily::Cooperative => &[
            MeetingChannel::Physical,
            MeetingChannel::Hybrid,
            MeetingChannel::Telematic,
            MeetingChannel::WrittenResolution,
        ],
    }
}

fn is_existing_authored_channel_compatibility(
    template_id: &str,
    family: EntityFamily,
    channel: MeetingChannel,
) -> bool {
    // Current-catalog compatibility only: preserve existing metadata while rejecting new drift.
    matches!(
        (template_id, family, channel),
        (
            "condominio-ata-assembleia/v1",
            EntityFamily::Condominium,
            MeetingChannel::WrittenResolution
        ) | (
            "fundacao-ata-ca/v1",
            EntityFamily::Foundation,
            MeetingChannel::WrittenResolution
        ) | (
            "fundacao-ata-orgao-fiscal/v1",
            EntityFamily::Foundation,
            MeetingChannel::WrittenResolution
        )
    )
}

fn expected_stage_for_template_id(template_id: &str) -> Option<LifecycleStage> {
    let stem = template_id_stem(template_id);
    if stem.contains("-convocatoria")
        || stem.contains("-aviso-convocatoria")
        || stem.contains("-procuracao-representacao")
        || stem.contains("-ponto-ordem-trabalhos")
    {
        Some(LifecycleStage::Convocatoria)
    } else if stem.contains("-termo-abertura") {
        Some(LifecycleStage::TermoAbertura)
    } else if stem.contains("-termo-encerramento") || stem.contains("-termo-transporte") {
        Some(LifecycleStage::TermoEncerramento)
    } else if stem.contains("-lista-presencas") || stem.contains("-registo-telematico") {
        Some(LifecycleStage::Reuniao)
    } else if stem.contains("-certidao-")
        || stem.contains("-declaracao-deliberacao")
        || stem.contains("-comunicacao-")
    {
        Some(LifecycleStage::Certidao)
    } else if stem.contains("-declaracao-voto") || stem.contains("-circular-deliberacao-escrito") {
        Some(LifecycleStage::Deliberacao)
    } else if stem.contains("-extrato-") {
        Some(LifecycleStage::Extrato)
    } else if stem.contains("-ata-")
        || stem.contains("-termo-retificacao")
        || stem.contains("-anexo-acordo-email")
    {
        Some(LifecycleStage::Ata)
    } else {
        None
    }
}

fn channel_order(channel: MeetingChannel) -> u8 {
    match channel {
        MeetingChannel::Physical => 0,
        MeetingChannel::Hybrid => 1,
        MeetingChannel::Telematic => 2,
        MeetingChannel::WrittenResolution => 3,
    }
}

fn expected_channels_for_template_id(template_id: &str) -> Option<Vec<MeetingChannel>> {
    let stem = template_id_stem(template_id);
    if stem.contains("-registo-telematico") {
        Some(vec![MeetingChannel::Telematic])
    } else if stem.contains("-circular-deliberacao-escrito") {
        Some(vec![MeetingChannel::WrittenResolution])
    } else {
        None
    }
}

fn requires_post_act_sealed_provenance(stage: LifecycleStage) -> bool {
    matches!(stage, LifecycleStage::Certidao | LifecycleStage::Extrato)
}

fn block_templates_bind_field(blocks: &[BlockSpec], field: &str) -> bool {
    blocks
        .iter()
        .any(|block| block_template_strings_bind_field(block, field))
}

fn block_template_strings_bind_field(block: &BlockSpec, field: &str) -> bool {
    match block {
        BlockSpec::Heading { template, .. } | BlockSpec::Paragraph { template, .. } => {
            template_string_binds_field(template, field)
        }
        BlockSpec::KeyValue { rows, .. } => rows.iter().any(|row| {
            template_string_binds_field(&row.key, field)
                || template_string_binds_field(&row.value, field)
        }),
        BlockSpec::VoteTable {
            label,
            unanimous_total,
            ..
        } => {
            template_string_binds_field(label, field)
                || unanimous_total
                    .as_deref()
                    .is_some_and(|template| template_string_binds_field(template, field))
        }
        BlockSpec::SignatureBlock { role, name, .. } => {
            template_string_binds_field(role, field) || template_string_binds_field(name, field)
        }
        BlockSpec::PageBreak | BlockSpec::Rule => false,
    }
}

fn template_string_binds_field(template: &str, field: &str) -> bool {
    let mut offset = 0;
    while let Some(start) = template[offset..].find('{').map(|start| offset + start) {
        let rest = &template[start..];
        let Some((open_len, close)) = rest
            .strip_prefix("{{")
            .map(|_| (2, "}}"))
            .or_else(|| rest.strip_prefix("{%").map(|_| (2, "%}")))
        else {
            offset = start + 1;
            continue;
        };

        let code_start = start + open_len;
        let Some(end) = template[code_start..]
            .find(close)
            .map(|end| code_start + end)
        else {
            break;
        };
        if template_code_binds_identifier(&template[code_start..end], field) {
            return true;
        }
        offset = end + close.len();
    }
    false
}

fn template_code_binds_identifier(code: &str, field: &str) -> bool {
    let mut chars = code.char_indices().peekable();
    let mut quote = None;
    while let Some((idx, ch)) = chars.next() {
        if let Some(expected_quote) = quote {
            if ch == '\\' {
                chars.next();
            } else if ch == expected_quote {
                quote = None;
            }
            continue;
        }

        if ch == '"' || ch == '\'' {
            quote = Some(ch);
            continue;
        }

        if !is_template_identifier_start(ch) {
            continue;
        }

        let start = idx;
        let mut end = idx + ch.len_utf8();
        while let Some(&(next_idx, next_ch)) = chars.peek() {
            if !is_template_identifier_continue(next_ch) {
                break;
            }
            chars.next();
            end = next_idx + next_ch.len_utf8();
        }

        if &code[start..end] == field && !is_attribute_lookup(code, start) {
            return true;
        }
    }
    false
}

fn is_template_identifier_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic()
}

fn is_template_identifier_continue(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

fn is_attribute_lookup(code: &str, identifier_start: usize) -> bool {
    code[..identifier_start]
        .chars()
        .rev()
        .find(|ch| !ch.is_whitespace())
        .is_some_and(|ch| ch == '.')
}
