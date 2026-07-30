//! Typed, bounded sample values used by stateless template previews.
//!
//! These settings are intentionally visible to principals with `act.read`: they are fictitious
//! authoring aids, never a place for production records, secrets, credentials or tokens.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use chancela_core::{
    DispatchChannel, EntityFamily, MeetingChannel, PresenceMode, SignatoryCapacity,
};
use chancela_templates::TemplateSpec;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::macros::format_description;
use time::{Date, Time};

const MAX_SERIALIZED_BYTES: usize = 256 * 1024;
const MAX_SHORT_CHARS: usize = 240;
const MAX_CONTACT_CHARS: usize = 500;
const MAX_PROSE_CHARS: usize = 2_000;
const MAX_PRIMARY_ITEMS: usize = 50;
const MAX_STATEMENTS: usize = 20;
const MAX_COUNT: u32 = 1_000_000;
const MAX_DOCUMENT_NUMBER: u32 = 999_999;
const MAX_ANTECEDENCE_DAYS: u32 = 3_650;
const MAX_PERMILAGE: u32 = 1_000;
const PRODUCT_DEFAULTS: &str = include_str!("template_preview_samples.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewSampleSettings {
    pub general: TemplatePreviewGeneral,
    pub entity: TemplatePreviewEntity,
    pub family_profiles: TemplatePreviewFamilyProfiles,
    pub book: TemplatePreviewBook,
    pub act: TemplatePreviewAct,
    pub meeting: TemplatePreviewMeeting,
    pub agenda: Vec<TemplatePreviewAgendaItem>,
    pub deliberations: TemplatePreviewDeliberations,
    pub evidence: TemplatePreviewEvidence,
    pub convening: TemplatePreviewConvening,
    pub convening_waiver: TemplatePreviewConveningWaiver,
    pub representation: TemplatePreviewRepresentation,
    pub telematic_evidence: TemplatePreviewTelematicEvidence,
    pub book_instruments: TemplatePreviewBookInstruments,
    pub fallbacks: TemplatePreviewFallbacks,
}

impl Default for TemplatePreviewSampleSettings {
    fn default() -> Self {
        static DEFAULTS: OnceLock<TemplatePreviewSampleSettings> = OnceLock::new();
        DEFAULTS
            .get_or_init(|| {
                serde_json::from_str(PRODUCT_DEFAULTS)
                    .expect("embedded template preview sample settings must be valid")
            })
            .clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewGeneral {
    pub title: String,
    pub subject: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewEntity {
    pub nipc: String,
    pub seat: String,
    pub address: String,
    pub share_capital: String,
    pub capital: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewFamilyProfiles {
    pub commercial_company: TemplatePreviewFamilyProfile,
    pub association: TemplatePreviewFamilyProfile,
    pub condominium: TemplatePreviewFamilyProfile,
    pub cooperative: TemplatePreviewFamilyProfile,
    pub foundation: TemplatePreviewFamilyProfile,
}

impl TemplatePreviewFamilyProfiles {
    fn for_family(&self, family: EntityFamily) -> &TemplatePreviewFamilyProfile {
        match family {
            EntityFamily::CommercialCompany => &self.commercial_company,
            EntityFamily::Condominium => &self.condominium,
            EntityFamily::Association => &self.association,
            EntityFamily::Foundation => &self.foundation,
            EntityFamily::Cooperative => &self.cooperative,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewFamilyProfile {
    pub name: String,
    pub legal_form: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewBook {
    pub kind: String,
    pub reference: String,
    pub predecessor_reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewAct {
    pub number: u32,
    pub title: String,
    pub meeting_date: String,
    pub meeting_time: String,
    pub place: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewMeeting {
    pub ata_number: u32,
    pub agenda_number: u32,
    pub meeting_date: String,
    pub meeting_time: String,
    pub place: String,
    pub channel: MeetingChannel,
    pub members_present: u32,
    pub members_represented: u32,
    pub attendance_reference: String,
    pub mesa: TemplatePreviewMesa,
    pub attendees: Vec<TemplatePreviewAttendee>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewMesa {
    pub president: String,
    pub secretaries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewAttendee {
    pub name: String,
    pub quality: SignatoryCapacity,
    pub quality_note: String,
    pub weight: TemplatePreviewWeight,
    pub presence: PresenceMode,
    pub represented_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewWeight {
    pub capital: Option<String>,
    pub permilage: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewAgendaItem {
    pub number: u32,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewDeliberations {
    pub summary: String,
    pub items: Vec<TemplatePreviewDeliberation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewDeliberation {
    pub agenda_number: u32,
    pub text: String,
    pub vote: TemplatePreviewVote,
    pub statements: Vec<TemplatePreviewStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemplatePreviewVote {
    Unanimous,
    Recorded {
        em_favor: u32,
        contra: u32,
        abstencoes: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewStatement {
    pub agenda_number: u32,
    pub member: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewEvidence {
    pub referenced_documents: Vec<TemplatePreviewReferencedDocument>,
    pub attachments: Vec<TemplatePreviewAttachment>,
    pub signatories: Vec<TemplatePreviewSignatory>,
    pub required_signatories: Vec<TemplatePreviewSignatory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewReferencedDocument {
    pub label: String,
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewAttachment {
    pub kind: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewSignatory {
    pub capacity: SignatoryCapacity,
    pub role: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewConvening {
    pub convener: String,
    pub convener_capacity: SignatoryCapacity,
    pub dispatch_date: String,
    pub antecedence_days: u32,
    pub channel: DispatchChannel,
    pub second_call: TemplatePreviewSecondCall,
    pub recipients: Vec<TemplatePreviewRecipient>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewSecondCall {
    pub date: String,
    pub time: String,
    pub reduced_quorum: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewRecipient {
    pub name: String,
    pub contact: String,
    pub channel: DispatchChannel,
    pub reference: String,
    pub dispatched_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewConveningWaiver {
    pub basis: String,
    pub all_agreed_to_meet: bool,
    pub all_agreed_to_agenda: bool,
    pub grounds: String,
    pub evidence_reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewRepresentation {
    pub scope: String,
    pub instructions: String,
    pub evidence_reference: String,
    pub representative: TemplatePreviewRepresentative,
    pub represented: TemplatePreviewRepresented,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewRepresentative {
    pub name: String,
    pub document: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewRepresented {
    pub name: String,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewTelematicEvidence {
    pub authenticity: String,
    pub recording: String,
    pub security: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemplatePreviewNumberingScheme {
    BoundVolume,
    LooseLeaf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemplatePreviewClosingReason {
    BookFull,
    EntityDissolved,
    MigrationToSuccessor,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewBookInstruments {
    pub opening_date: String,
    pub closing_date: String,
    pub numbering_scheme: TemplatePreviewNumberingScheme,
    pub numbering_label: String,
    pub purpose: String,
    pub ata_count: u32,
    pub closing_reason: TemplatePreviewClosingReason,
    pub rectifies: String,
    pub seal_event_seq: u32,
    pub payload_digest: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewFallbacks {
    pub capacity: SignatoryCapacity,
    pub contact: String,
    pub dispatched_at: String,
    pub kind: String,
    pub label: String,
    pub name: String,
    pub number: u32,
    pub quality: SignatoryCapacity,
    pub quality_note: String,
    pub reference: String,
    pub represented_by: String,
    pub role: String,
    pub statement: TemplatePreviewStatement,
    pub text: String,
    pub weight: TemplatePreviewFallbackWeight,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePreviewFallbackWeight {
    pub capital: String,
    pub permilage: u32,
}

impl TemplatePreviewSampleSettings {
    pub(crate) fn validate(&self) -> Result<(), String> {
        let serialized_len = serde_json::to_vec(self)
            .map_err(|error| format!("documents.template_preview_samples: {error}"))?
            .len();
        if serialized_len > MAX_SERIALIZED_BYTES {
            return Err(format!(
                "root must serialize to at most {MAX_SERIALIZED_BYTES} bytes, got {serialized_len}"
            ));
        }

        short("general.title", &self.general.title)?;
        optional_short("general.subject", &self.general.subject)?;
        iso_date("general.created_at", &self.general.created_at)?;
        if self.entity.nipc.len() != 9
            || !self.entity.nipc.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(
                "entity.nipc must contain exactly 9 ASCII digits (for example 500000000)"
                    .to_owned(),
            );
        }
        contact("entity.seat", &self.entity.seat)?;
        contact("entity.address", &self.entity.address)?;
        short("entity.share_capital", &self.entity.share_capital)?;
        short("entity.capital", &self.entity.capital)?;
        for (path, profile) in [
            (
                "family_profiles.commercial_company",
                &self.family_profiles.commercial_company,
            ),
            (
                "family_profiles.association",
                &self.family_profiles.association,
            ),
            (
                "family_profiles.condominium",
                &self.family_profiles.condominium,
            ),
            (
                "family_profiles.cooperative",
                &self.family_profiles.cooperative,
            ),
            (
                "family_profiles.foundation",
                &self.family_profiles.foundation,
            ),
        ] {
            short(&format!("{path}.name"), &profile.name)?;
            short(&format!("{path}.legal_form"), &profile.legal_form)?;
        }
        short("book.kind", &self.book.kind)?;
        short("book.reference", &self.book.reference)?;
        short(
            "book.predecessor_reference",
            &self.book.predecessor_reference,
        )?;

        number("act.number", self.act.number)?;
        short("act.title", &self.act.title)?;
        iso_date("act.meeting_date", &self.act.meeting_date)?;
        hh_mm("act.meeting_time", &self.act.meeting_time)?;
        contact("act.place", &self.act.place)?;

        number("meeting.ata_number", self.meeting.ata_number)?;
        number("meeting.agenda_number", self.meeting.agenda_number)?;
        iso_date("meeting.meeting_date", &self.meeting.meeting_date)?;
        hh_mm("meeting.meeting_time", &self.meeting.meeting_time)?;
        contact("meeting.place", &self.meeting.place)?;
        count("meeting.members_present", self.meeting.members_present)?;
        count(
            "meeting.members_represented",
            self.meeting.members_represented,
        )?;
        short(
            "meeting.attendance_reference",
            &self.meeting.attendance_reference,
        )?;
        short("meeting.mesa.president", &self.meeting.mesa.president)?;
        if !(1..=10).contains(&self.meeting.mesa.secretaries.len()) {
            return Err(format!(
                "meeting.mesa.secretaries must contain between 1 and 10 entries, got {}",
                self.meeting.mesa.secretaries.len()
            ));
        }
        for (index, secretary) in self.meeting.mesa.secretaries.iter().enumerate() {
            short(&format!("meeting.mesa.secretaries[{index}]"), secretary)?;
        }
        collection("meeting.attendees", &self.meeting.attendees)?;
        for (index, attendee) in self.meeting.attendees.iter().enumerate() {
            let path = format!("meeting.attendees[{index}]");
            short(&format!("{path}.name"), &attendee.name)?;
            short(&format!("{path}.quality_note"), &attendee.quality_note)?;
            if let Some(represented_by) = &attendee.represented_by {
                short(&format!("{path}.represented_by"), represented_by)?;
            }
            if let Some(capital) = &attendee.weight.capital {
                short(&format!("{path}.weight.capital"), capital)?;
            }
            if let Some(permilage) = attendee.weight.permilage {
                permilage_value(&format!("{path}.weight.permilage"), permilage)?;
            }
        }

        collection("agenda", &self.agenda)?;
        let mut agenda_numbers = BTreeSet::new();
        for (index, item) in self.agenda.iter().enumerate() {
            number(&format!("agenda[{index}].number"), item.number)?;
            if !agenda_numbers.insert(item.number) {
                return Err(format!(
                    "agenda[{index}].number must be unique, got duplicate {}",
                    item.number
                ));
            }
            prose(&format!("agenda[{index}].text"), &item.text)?;
        }

        prose("deliberations.summary", &self.deliberations.summary)?;
        collection("deliberations.items", &self.deliberations.items)?;
        let mut deliberation_numbers = BTreeSet::new();
        for (index, item) in self.deliberations.items.iter().enumerate() {
            let path = format!("deliberations.items[{index}]");
            number(&format!("{path}.agenda_number"), item.agenda_number)?;
            if !deliberation_numbers.insert(item.agenda_number) {
                return Err(format!(
                    "{path}.agenda_number must be unique, got duplicate {}",
                    item.agenda_number
                ));
            }
            prose(&format!("{path}.text"), &item.text)?;
            if let TemplatePreviewVote::Recorded {
                em_favor,
                contra,
                abstencoes,
            } = item.vote
            {
                count(&format!("{path}.vote.Recorded.em_favor"), em_favor)?;
                count(&format!("{path}.vote.Recorded.contra"), contra)?;
                count(&format!("{path}.vote.Recorded.abstencoes"), abstencoes)?;
            }
            if item.statements.len() > MAX_STATEMENTS {
                return Err(format!(
                    "{path}.statements accepts at most {MAX_STATEMENTS} entries, got {}",
                    item.statements.len()
                ));
            }
            for (statement_index, statement) in item.statements.iter().enumerate() {
                validate_statement(&format!("{path}.statements[{statement_index}]"), statement)?;
            }
        }

        collection(
            "evidence.referenced_documents",
            &self.evidence.referenced_documents,
        )?;
        for (index, document) in self.evidence.referenced_documents.iter().enumerate() {
            short(
                &format!("evidence.referenced_documents[{index}].label"),
                &document.label,
            )?;
            short(
                &format!("evidence.referenced_documents[{index}].reference"),
                &document.reference,
            )?;
        }
        collection("evidence.attachments", &self.evidence.attachments)?;
        for (index, attachment) in self.evidence.attachments.iter().enumerate() {
            short(
                &format!("evidence.attachments[{index}].kind"),
                &attachment.kind,
            )?;
            digest(
                &format!("evidence.attachments[{index}].digest"),
                &attachment.digest,
            )?;
        }
        collection("evidence.signatories", &self.evidence.signatories)?;
        collection(
            "evidence.required_signatories",
            &self.evidence.required_signatories,
        )?;
        for (path, values) in [
            ("evidence.signatories", &self.evidence.signatories),
            (
                "evidence.required_signatories",
                &self.evidence.required_signatories,
            ),
        ] {
            for (index, signatory) in values.iter().enumerate() {
                short(&format!("{path}[{index}].role"), &signatory.role)?;
                short(&format!("{path}[{index}].name"), &signatory.name)?;
            }
        }

        short("convening.convener", &self.convening.convener)?;
        iso_date("convening.dispatch_date", &self.convening.dispatch_date)?;
        if self.convening.antecedence_days > MAX_ANTECEDENCE_DAYS {
            return Err(format!(
                "convening.antecedence_days must be at most {MAX_ANTECEDENCE_DAYS}, got {}",
                self.convening.antecedence_days
            ));
        }
        iso_date(
            "convening.second_call.date",
            &self.convening.second_call.date,
        )?;
        hh_mm(
            "convening.second_call.time",
            &self.convening.second_call.time,
        )?;
        collection("convening.recipients", &self.convening.recipients)?;
        for (index, recipient) in self.convening.recipients.iter().enumerate() {
            let path = format!("convening.recipients[{index}]");
            short(&format!("{path}.name"), &recipient.name)?;
            contact(&format!("{path}.contact"), &recipient.contact)?;
            short(&format!("{path}.reference"), &recipient.reference)?;
            iso_date(&format!("{path}.dispatched_at"), &recipient.dispatched_at)?;
        }

        short("convening_waiver.basis", &self.convening_waiver.basis)?;
        prose("convening_waiver.grounds", &self.convening_waiver.grounds)?;
        short(
            "convening_waiver.evidence_reference",
            &self.convening_waiver.evidence_reference,
        )?;
        prose("representation.scope", &self.representation.scope)?;
        prose(
            "representation.instructions",
            &self.representation.instructions,
        )?;
        short(
            "representation.evidence_reference",
            &self.representation.evidence_reference,
        )?;
        short(
            "representation.representative.name",
            &self.representation.representative.name,
        )?;
        short(
            "representation.representative.document",
            &self.representation.representative.document,
        )?;
        short(
            "representation.represented.name",
            &self.representation.represented.name,
        )?;
        short(
            "representation.represented.unit",
            &self.representation.represented.unit,
        )?;
        prose(
            "telematic_evidence.authenticity",
            &self.telematic_evidence.authenticity,
        )?;
        prose(
            "telematic_evidence.recording",
            &self.telematic_evidence.recording,
        )?;
        prose(
            "telematic_evidence.security",
            &self.telematic_evidence.security,
        )?;

        iso_date(
            "book_instruments.opening_date",
            &self.book_instruments.opening_date,
        )?;
        iso_date(
            "book_instruments.closing_date",
            &self.book_instruments.closing_date,
        )?;
        short(
            "book_instruments.numbering_label",
            &self.book_instruments.numbering_label,
        )?;
        prose("book_instruments.purpose", &self.book_instruments.purpose)?;
        count(
            "book_instruments.ata_count",
            self.book_instruments.ata_count,
        )?;
        short(
            "book_instruments.rectifies",
            &self.book_instruments.rectifies,
        )?;
        count(
            "book_instruments.seal_event_seq",
            self.book_instruments.seal_event_seq,
        )?;
        digest(
            "book_instruments.payload_digest",
            &self.book_instruments.payload_digest,
        )?;
        digest("book_instruments.digest", &self.book_instruments.digest)?;

        contact("fallbacks.contact", &self.fallbacks.contact)?;
        iso_date("fallbacks.dispatched_at", &self.fallbacks.dispatched_at)?;
        short("fallbacks.kind", &self.fallbacks.kind)?;
        short("fallbacks.label", &self.fallbacks.label)?;
        short("fallbacks.name", &self.fallbacks.name)?;
        number("fallbacks.number", self.fallbacks.number)?;
        short("fallbacks.quality_note", &self.fallbacks.quality_note)?;
        short("fallbacks.reference", &self.fallbacks.reference)?;
        short("fallbacks.represented_by", &self.fallbacks.represented_by)?;
        short("fallbacks.role", &self.fallbacks.role)?;
        validate_statement("fallbacks.statement", &self.fallbacks.statement)?;
        prose("fallbacks.text", &self.fallbacks.text)?;
        short("fallbacks.weight.capital", &self.fallbacks.weight.capital)?;
        permilage_value(
            "fallbacks.weight.permilage",
            self.fallbacks.weight.permilage,
        )?;
        Ok(())
    }
}

fn collection<T>(path: &str, values: &[T]) -> Result<(), String> {
    if !(1..=MAX_PRIMARY_ITEMS).contains(&values.len()) {
        return Err(format!(
            "{path} must contain between 1 and {MAX_PRIMARY_ITEMS} entries, got {}",
            values.len()
        ));
    }
    Ok(())
}

fn text(path: &str, value: &str, max: usize, allow_blank: bool) -> Result<(), String> {
    let chars = value.chars().count();
    if (!allow_blank && value.trim().is_empty())
        || chars > max
        || value.chars().any(char::is_control)
    {
        let blank = if allow_blank { "" } else { "non-blank " };
        return Err(format!(
            "{path} must be {blank}text without control characters and at most {max} characters, \
             got {chars}"
        ));
    }
    Ok(())
}

fn short(path: &str, value: &str) -> Result<(), String> {
    text(path, value, MAX_SHORT_CHARS, false)
}

fn optional_short(path: &str, value: &str) -> Result<(), String> {
    text(path, value, MAX_SHORT_CHARS, true)
}

fn contact(path: &str, value: &str) -> Result<(), String> {
    text(path, value, MAX_CONTACT_CHARS, false)
}

fn prose(path: &str, value: &str) -> Result<(), String> {
    let chars = value.chars().count();
    if value.trim().is_empty()
        || chars > MAX_PROSE_CHARS
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\r' | '\n' | '\t'))
    {
        return Err(format!(
            "{path} must be non-blank prose without unsupported control characters and at most \
             {MAX_PROSE_CHARS} characters, got {chars}"
        ));
    }
    Ok(())
}

fn number(path: &str, value: u32) -> Result<(), String> {
    if !(1..=MAX_DOCUMENT_NUMBER).contains(&value) {
        return Err(format!(
            "{path} must be between 1 and {MAX_DOCUMENT_NUMBER}, got {value}"
        ));
    }
    Ok(())
}

fn count(path: &str, value: u32) -> Result<(), String> {
    if value > MAX_COUNT {
        return Err(format!("{path} must be at most {MAX_COUNT}, got {value}"));
    }
    Ok(())
}

fn permilage_value(path: &str, value: u32) -> Result<(), String> {
    if value > MAX_PERMILAGE {
        return Err(format!(
            "{path} must be at most {MAX_PERMILAGE}, got {value}"
        ));
    }
    Ok(())
}

fn iso_date(path: &str, value: &str) -> Result<(), String> {
    if value.len() != 10
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
    {
        return Err(format!(
            "{path} must be an ISO date in YYYY-MM-DD format, got {value:?}"
        ));
    }
    Date::parse(value, &format_description!("[year]-[month]-[day]"))
        .map(|_| ())
        .map_err(|_| format!("{path} must be an ISO date in YYYY-MM-DD format, got {value:?}"))
}

fn hh_mm(path: &str, value: &str) -> Result<(), String> {
    if value.len() != 5 || value.as_bytes().get(2) != Some(&b':') {
        return Err(format!(
            "{path} must be a 24-hour time in HH:MM format, got {value:?}"
        ));
    }
    Time::parse(value, &format_description!("[hour]:[minute]"))
        .map(|_| ())
        .map_err(|_| format!("{path} must be a 24-hour time in HH:MM format, got {value:?}"))
}

fn digest(path: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{path} must be exactly 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn validate_statement(path: &str, statement: &TemplatePreviewStatement) -> Result<(), String> {
    number(&format!("{path}.agenda_number"), statement.agenda_number)?;
    short(&format!("{path}.member"), &statement.member)?;
    prose(&format!("{path}.text"), &statement.text)
}

fn serialized<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("typed template preview value must serialize")
}

fn insert(map: &mut Map<String, Value>, key: &str, value: Value) {
    assert!(
        map.insert(key.to_owned(), value).is_none(),
        "template preview context key collision: {key}"
    );
}

fn insert_string(map: &mut Map<String, Value>, key: &str, value: &str) {
    insert(map, key, Value::String(value.to_owned()));
}

fn attendee_context(attendee: &TemplatePreviewAttendee) -> Value {
    let mut row = match serialized(attendee) {
        Value::Object(row) => row,
        _ => unreachable!("an attendee serializes as an object"),
    };
    let mut weight = Map::new();
    if let Some(capital) = &attendee.weight.capital {
        insert_string(&mut weight, "Capital", capital);
    }
    if let Some(permilage) = attendee.weight.permilage {
        insert(&mut weight, "Permilage", Value::from(permilage));
    }
    row.insert("weight".to_owned(), Value::Object(weight));
    Value::Object(row)
}

/// Build the complete sample render context from one validated settings snapshot.
///
/// Family routing is based only on the spec's typed family. User-template IDs are arbitrary and
/// never participate. The company transport template's historical string predecessor and the
/// structured predecessor used by all other families are adapted here without exposing two
/// competing settings fields.
pub(crate) fn template_preview_sample_context(
    spec: &TemplateSpec,
    samples: &TemplatePreviewSampleSettings,
) -> Value {
    let mut context = Map::new();
    insert_string(&mut context, "title", &samples.general.title);
    insert_string(&mut context, "subject", &samples.general.subject);
    insert_string(&mut context, "created_at", &samples.general.created_at);

    let profile = samples.family_profiles.for_family(spec.family);
    let mut entity = Map::new();
    insert_string(&mut entity, "name", &profile.name);
    insert_string(&mut entity, "nipc", &samples.entity.nipc);
    insert_string(&mut entity, "legal_form", &profile.legal_form);
    insert_string(&mut entity, "seat", &samples.entity.seat);
    insert_string(&mut entity, "address", &samples.entity.address);
    insert_string(&mut entity, "share_capital", &samples.entity.share_capital);
    insert_string(&mut entity, "capital", &samples.entity.capital);
    insert(&mut context, "entity", Value::Object(entity));

    let mut book = Map::new();
    insert_string(&mut book, "kind", &samples.book.kind);
    insert_string(&mut book, "reference", &samples.book.reference);
    let predecessor = if spec.family == EntityFamily::CommercialCompany {
        Value::String(samples.book.predecessor_reference.clone())
    } else {
        let mut predecessor = Map::new();
        insert_string(
            &mut predecessor,
            "book_reference",
            &samples.book.predecessor_reference,
        );
        Value::Object(predecessor)
    };
    insert(&mut book, "predecessor", predecessor);
    insert(&mut context, "book", Value::Object(book));
    insert(&mut context, "act", serialized(&samples.act));

    for (key, value) in [
        ("ata_number", Value::from(samples.meeting.ata_number)),
        ("agenda_number", Value::from(samples.meeting.agenda_number)),
        (
            "meeting_date",
            Value::String(samples.meeting.meeting_date.clone()),
        ),
        (
            "meeting_time",
            Value::String(samples.meeting.meeting_time.clone()),
        ),
        ("place", Value::String(samples.meeting.place.clone())),
        ("channel", serialized(&samples.meeting.channel)),
        (
            "members_present",
            Value::from(samples.meeting.members_present),
        ),
        (
            "members_represented",
            Value::from(samples.meeting.members_represented),
        ),
        (
            "attendance_reference",
            Value::String(samples.meeting.attendance_reference.clone()),
        ),
    ] {
        insert(&mut context, key, value);
    }
    let mut mesa = Map::new();
    insert_string(&mut mesa, "presidente", &samples.meeting.mesa.president);
    insert(
        &mut mesa,
        "secretarios",
        serialized(&samples.meeting.mesa.secretaries),
    );
    insert(&mut context, "mesa", Value::Object(mesa));
    insert(
        &mut context,
        "attendees",
        Value::Array(
            samples
                .meeting
                .attendees
                .iter()
                .map(attendee_context)
                .collect(),
        ),
    );
    insert(&mut context, "agenda", serialized(&samples.agenda));
    insert_string(
        &mut context,
        "deliberations",
        &samples.deliberations.summary,
    );
    insert(
        &mut context,
        "deliberation_items",
        serialized(&samples.deliberations.items),
    );
    insert(
        &mut context,
        "referenced_documents",
        serialized(&samples.evidence.referenced_documents),
    );
    insert(
        &mut context,
        "attachments",
        serialized(&samples.evidence.attachments),
    );
    insert(
        &mut context,
        "signatories",
        serialized(&samples.evidence.signatories),
    );
    insert(
        &mut context,
        "required_signatories",
        serialized(&samples.evidence.required_signatories),
    );
    insert(&mut context, "convening", serialized(&samples.convening));
    insert(
        &mut context,
        "convening_waiver",
        serialized(&samples.convening_waiver),
    );

    let mut representation = Map::new();
    insert_string(&mut representation, "scope", &samples.representation.scope);
    insert_string(
        &mut representation,
        "instructions",
        &samples.representation.instructions,
    );
    insert_string(
        &mut representation,
        "evidence_reference",
        &samples.representation.evidence_reference,
    );
    insert(
        &mut context,
        "representation",
        Value::Object(representation),
    );
    insert(
        &mut context,
        "representative",
        serialized(&samples.representation.representative),
    );
    insert(
        &mut context,
        "represented",
        serialized(&samples.representation.represented),
    );
    insert(
        &mut context,
        "telematic_evidence",
        serialized(&samples.telematic_evidence),
    );

    // A termo's fillable clauses. Unlike every other key here this one is NOT a settings sample:
    // the clauses a template preview should show are that template's own seed, so it comes from the
    // spec. Without it a template placing a clause-body block would preview with no clause section
    // at all and say nothing about it — the same silent omission the clause-body mint exists to fix.
    insert(
        &mut context,
        "body",
        Value::Array(
            spec.default_body()
                .iter()
                .map(|clause| {
                    let mut row = Map::new();
                    if let Some(heading) =
                        clause.heading.as_deref().filter(|h| !h.trim().is_empty())
                    {
                        insert_string(&mut row, "heading", heading);
                    }
                    insert_string(&mut row, "text", &clause.text);
                    Value::Object(row)
                })
                .collect(),
        ),
    );

    let law_references = spec
        .law_references
        .iter()
        .map(|reference| {
            let mut value = Map::new();
            insert_string(&mut value, "source_id", &reference.source_id);
            insert_string(&mut value, "source_label", &reference.source_label);
            insert_string(&mut value, "citation", &reference.citation);
            insert(&mut value, "article", serialized(&reference.article));
            insert(
                &mut value,
                "verification",
                serialized(&reference.verification),
            );
            Value::Object(value)
        })
        .collect();
    insert(&mut context, "law_references", Value::Array(law_references));

    for (key, value) in [
        (
            "opening_date",
            Value::String(samples.book_instruments.opening_date.clone()),
        ),
        (
            "closing_date",
            Value::String(samples.book_instruments.closing_date.clone()),
        ),
        (
            "numbering_scheme",
            serialized(&samples.book_instruments.numbering_scheme),
        ),
        (
            "numbering_label",
            Value::String(samples.book_instruments.numbering_label.clone()),
        ),
        (
            "purpose",
            Value::String(samples.book_instruments.purpose.clone()),
        ),
        ("ata_count", Value::from(samples.book_instruments.ata_count)),
        (
            "reason",
            serialized(&samples.book_instruments.closing_reason),
        ),
        (
            "retifies",
            Value::String(samples.book_instruments.rectifies.clone()),
        ),
        (
            "seal_event_seq",
            Value::from(samples.book_instruments.seal_event_seq),
        ),
        (
            "payload_digest",
            Value::String(samples.book_instruments.payload_digest.clone()),
        ),
        (
            "digest",
            Value::String(samples.book_instruments.digest.clone()),
        ),
    ] {
        insert(&mut context, key, value);
    }

    let fallbacks = serialized(&samples.fallbacks);
    let mut fallbacks = match fallbacks {
        Value::Object(fallbacks) => fallbacks,
        _ => unreachable!("fallbacks serialize as an object"),
    };
    fallbacks.remove("weight");
    for (key, value) in fallbacks {
        insert(&mut context, &key, value);
    }
    let mut fallback_weight = Map::new();
    insert_string(
        &mut fallback_weight,
        "Capital",
        &samples.fallbacks.weight.capital,
    );
    insert(
        &mut fallback_weight,
        "Permilage",
        Value::from(samples.fallbacks.weight.permilage),
    );
    insert(&mut context, "weight", Value::Object(fallback_weight));

    Value::Object(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_templates::load_registry;

    type PreviewSettingsMutation = Box<dyn Fn(&mut TemplatePreviewSampleSettings)>;

    #[test]
    fn defaults_are_valid_and_match_the_pinned_product_and_settings_contract_fixtures() {
        let defaults = TemplatePreviewSampleSettings::default();
        defaults.validate().expect("product defaults validate");
        let fixture: Value = serde_json::from_str(PRODUCT_DEFAULTS).expect("fixture parses");
        let defaults_json = serialized(&defaults);
        assert_eq!(defaults_json, fixture);
        let settings_contract: Value =
            serde_json::from_str(include_str!("../../../contracts/settings.json"))
                .expect("settings contract parses");
        assert_eq!(
            settings_contract.pointer("/documents/template_preview_samples"),
            Some(&defaults_json),
            "the Rust product default and committed settings wire contract must stay identical"
        );
    }

    #[test]
    fn family_profiles_and_predecessors_follow_typed_family_not_id_prefix() {
        let defaults = TemplatePreviewSampleSettings::default();
        let expected = [
            (
                EntityFamily::CommercialCompany,
                ("Sociedade Exemplo, Lda.", false),
            ),
            (
                EntityFamily::Association,
                ("Associação Cultural Exemplo", true),
            ),
            (
                EntityFamily::Condominium,
                ("Condomínio do Edifício Exemplo", true),
            ),
            (
                EntityFamily::Cooperative,
                ("Cooperativa Exemplo, C.R.L.", true),
            ),
            (EntityFamily::Foundation, ("Fundação Exemplo", true)),
        ];
        let registry = load_registry().expect("catalog loads");
        for (family, (name, structured_predecessor)) in expected {
            let mut spec = registry
                .specs()
                .iter()
                .find(|spec| spec.family == family)
                .unwrap_or_else(|| panic!("catalog must contain {family:?}"))
                .clone();
            spec.id = "custom-id-with-deliberately-wrong-prefix/v1".to_owned();
            let context = template_preview_sample_context(&spec, &defaults);
            assert_eq!(context.pointer("/entity/name"), Some(&Value::from(name)));
            assert_eq!(
                context
                    .pointer("/book/predecessor")
                    .is_some_and(Value::is_object),
                structured_predecessor
            );
        }
    }

    #[test]
    fn context_preserves_legacy_names_external_weights_and_statement_agenda() {
        let defaults = TemplatePreviewSampleSettings::default();
        let registry = load_registry().expect("catalog loads");
        let spec = registry
            .specs()
            .iter()
            .find(|spec| spec.family == EntityFamily::CommercialCompany)
            .expect("company template");
        let context = template_preview_sample_context(spec, &defaults);
        assert_eq!(
            context.pointer("/mesa/presidente"),
            Some(&Value::from("Ana Martins"))
        );
        assert_eq!(
            context.pointer("/deliberations"),
            Some(&Value::from(
                "As propostas constantes da ordem de trabalhos foram discutidas e votadas."
            ))
        );
        assert_eq!(context.pointer("/reason"), Some(&Value::from("BookFull")));
        assert_eq!(
            context.pointer("/retifies"),
            Some(&Value::from("Ata n.º 11, de 30 de junho de 2026"))
        );
        assert_eq!(
            context.pointer("/attendees/0/weight/Capital"),
            Some(&Value::from("60 000,00 EUR"))
        );
        assert_eq!(
            context.pointer("/attendees/2/weight/Permilage"),
            Some(&Value::from(125))
        );
        assert_eq!(
            context.pointer("/deliberation_items/0/statements/0/agenda_number"),
            Some(&Value::from(1))
        );
        assert_eq!(
            context.pointer("/statement/agenda_number"),
            Some(&Value::from(1))
        );
        assert_eq!(
            context.pointer("/law_references/0/source_id"),
            spec.law_references
                .first()
                .map(|reference| Value::from(reference.source_id.clone()))
                .as_ref()
        );
    }

    #[test]
    fn validation_reports_actionable_paths_for_important_bounds_and_formats() {
        let cases: Vec<(&str, PreviewSettingsMutation)> = vec![
            ("general.title", Box::new(|s| s.general.title.clear())),
            (
                "general.title",
                Box::new(|s| s.general.title = "x".repeat(MAX_SHORT_CHARS + 1)),
            ),
            (
                "entity.nipc",
                Box::new(|s| s.entity.nipc = "12345678x".to_owned()),
            ),
            (
                "entity.address",
                Box::new(|s| s.entity.address = "x".repeat(MAX_CONTACT_CHARS + 1)),
            ),
            (
                "act.number",
                Box::new(|s| s.act.number = MAX_DOCUMENT_NUMBER + 1),
            ),
            (
                "meeting.meeting_date",
                Box::new(|s| s.meeting.meeting_date = "2026-02-30".to_owned()),
            ),
            (
                "meeting.meeting_time",
                Box::new(|s| s.meeting.meeting_time = "25:00".to_owned()),
            ),
            (
                "meeting.members_present",
                Box::new(|s| s.meeting.members_present = MAX_COUNT + 1),
            ),
            (
                "meeting.mesa.secretaries",
                Box::new(|s| s.meeting.mesa.secretaries.clear()),
            ),
            (
                "meeting.attendees",
                Box::new(|s| {
                    let row = s.meeting.attendees[0].clone();
                    s.meeting.attendees = vec![row; MAX_PRIMARY_ITEMS + 1];
                }),
            ),
            (
                "agenda[1].number",
                Box::new(|s| s.agenda[1].number = s.agenda[0].number),
            ),
            (
                "agenda[0].text",
                Box::new(|s| s.agenda[0].text = "x".repeat(MAX_PROSE_CHARS + 1)),
            ),
            (
                "statements accepts at most",
                Box::new(|s| {
                    let row = s.deliberations.items[0].statements[0].clone();
                    s.deliberations.items[0].statements = vec![row; MAX_STATEMENTS + 1];
                }),
            ),
            (
                "evidence.attachments[0].digest",
                Box::new(|s| s.evidence.attachments[0].digest = "A".repeat(64)),
            ),
            (
                "convening.antecedence_days",
                Box::new(|s| s.convening.antecedence_days = MAX_ANTECEDENCE_DAYS + 1),
            ),
            (
                "fallbacks.weight.permilage",
                Box::new(|s| s.fallbacks.weight.permilage = MAX_PERMILAGE + 1),
            ),
        ];
        for (expected_path, mutate) in cases {
            let mut settings = TemplatePreviewSampleSettings::default();
            mutate(&mut settings);
            let error = match settings.validate() {
                Ok(()) => panic!("{expected_path} should be rejected"),
                Err(error) => error,
            };
            assert!(
                error.contains(expected_path),
                "expected {expected_path:?} in {error:?}"
            );
        }
    }

    #[test]
    fn place_fields_accept_500_unicode_scalars_and_reject_501() {
        for set_place in [
            (|settings: &mut TemplatePreviewSampleSettings, value: String| {
                settings.act.place = value;
            }) as fn(&mut TemplatePreviewSampleSettings, String),
            |settings: &mut TemplatePreviewSampleSettings, value: String| {
                settings.meeting.place = value;
            },
        ] {
            let mut settings = TemplatePreviewSampleSettings::default();
            set_place(&mut settings, "á".repeat(MAX_CONTACT_CHARS));
            settings
                .validate()
                .expect("exactly 500 Unicode scalars must be accepted");

            set_place(&mut settings, "á".repeat(MAX_CONTACT_CHARS + 1));
            let error = settings
                .validate()
                .expect_err("501 Unicode scalars must be rejected");
            assert!(error.contains("at most 500 characters"));
            assert!(error.contains("got 501"));
        }
    }

    #[test]
    fn validation_rejects_the_total_serialized_size_even_when_individual_fields_are_bounded() {
        let mut settings = TemplatePreviewSampleSettings::default();
        let mut statement = settings.deliberations.items[0].statements[0].clone();
        statement.text = "x".repeat(MAX_PROSE_CHARS);
        settings.deliberations.items[0].statements = vec![statement; MAX_STATEMENTS];
        settings.deliberations.items =
            vec![settings.deliberations.items[0].clone(); MAX_PRIMARY_ITEMS];
        let error = settings
            .validate()
            .expect_err("oversized aggregate must be rejected");
        assert!(error.contains("root"));
        assert!(error.contains("262144"));
    }

    #[test]
    fn subject_is_the_intentionally_blank_product_field() {
        let defaults = TemplatePreviewSampleSettings::default();
        assert!(defaults.general.subject.is_empty());
        defaults.validate().expect("blank subject stays valid");
    }
}
