use std::collections::BTreeSet;
use std::sync::LazyLock;

use chancela_core::{Act, LifecycleStage, PresenceMode};
use chancela_templates::Registry;
use serde::Serialize;

pub(crate) const CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID: &str =
    "condominio-comunicacao-ausentes/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GeneratedDispatchEvidenceProfile {
    AbsentOwnerCommunication,
    GeneratedConveningNotice,
}

impl GeneratedDispatchEvidenceProfile {
    fn uncovered_note(self) -> String {
        match self {
            Self::AbsentOwnerCommunication => {
                "communication generated automatically; operator-recorded dispatch evidence does not cover every required absent recipient"
                    .to_owned()
            }
            Self::GeneratedConveningNotice => {
                "generated convening notice has operator-recorded dispatch evidence pending for one or more required recipients; no sending, delivery, legal notice completion, or legal sufficiency is claimed"
                    .to_owned()
            }
        }
    }

    fn covered_note(self) -> String {
        match self {
            Self::AbsentOwnerCommunication => {
                "operator-recorded dispatch evidence covers all absent recipients, but no sending, delivery, legal notice completion, or legal sufficiency is claimed"
                    .to_owned()
            }
            Self::GeneratedConveningNotice => {
                "operator-recorded dispatch evidence covers all generated convening notice recipients, but no sending, delivery, legal notice completion, or legal sufficiency is claimed"
                    .to_owned()
            }
        }
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct DispatchEvidenceStatusView {
    pub status: String,
    pub required: bool,
    pub evidence_attached: bool,
    pub dispatch_completed: bool,
    pub completion_basis: &'static str,
    pub required_recipients: Vec<String>,
    pub recorded_recipients: Vec<String>,
    pub missing_recipients: Vec<String>,
    pub note: String,
}

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    chancela_templates::load_registry().expect("embedded template registry loads")
});

pub(crate) fn generated_dispatch_evidence_profile_for_template(
    template_id: &str,
) -> Option<GeneratedDispatchEvidenceProfile> {
    if template_id == CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID {
        return Some(GeneratedDispatchEvidenceProfile::AbsentOwnerCommunication);
    }
    let spec = REGISTRY.get(template_id)?;
    if spec.stage == LifecycleStage::Convocatoria {
        return Some(GeneratedDispatchEvidenceProfile::GeneratedConveningNotice);
    }
    None
}

pub(crate) fn generated_dispatch_required_recipient_names(
    act: &Act,
    template_id: &str,
) -> Option<Vec<String>> {
    let profile = generated_dispatch_evidence_profile_for_template(template_id)?;
    Some(match profile {
        GeneratedDispatchEvidenceProfile::AbsentOwnerCommunication => {
            absent_owner_recipient_names(act)
        }
        GeneratedDispatchEvidenceProfile::GeneratedConveningNotice => {
            convening_recipient_names(act)
        }
    })
}

pub(crate) fn dispatch_evidence_status_for_template(
    template_id: &str,
    required_recipients: &[String],
    recorded_recipients: &[String],
) -> Option<DispatchEvidenceStatusView> {
    let profile = generated_dispatch_evidence_profile_for_template(template_id)?;
    // Both sides are matched on their trimmed form. Operator-recorded evidence is free text a
    // human pasted, so a recipient served with a trailing space used to miss the required name by
    // one character and stay listed as never served — a false negative on an evidentiary surface,
    // and one the operator had no way to clear. Blank required names are dropped here rather than
    // filtered later, so they cannot sit in `missing` forever and make coverage unreachable.
    let required: Vec<&str> = required_recipients
        .iter()
        .map(|name| name.trim())
        .filter(|name| !name.is_empty())
        .collect();
    let required_set: BTreeSet<&str> = required.iter().copied().collect();
    let recorded_set: BTreeSet<&str> = recorded_recipients
        .iter()
        .map(|name| name.trim())
        .filter(|name| required_set.contains(name))
        .collect();
    let recorded = required
        .iter()
        .filter(|name| recorded_set.contains(*name))
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    let missing = required
        .iter()
        .filter(|name| !recorded_set.contains(*name))
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    let evidence_attached = !recorded.is_empty();
    let all_required_recipients_covered = !required_set.is_empty() && missing.is_empty();
    Some(DispatchEvidenceStatusView {
        status: if all_required_recipients_covered {
            "operator_evidence_covered".to_owned()
        } else if recorded.is_empty() {
            "required_pending".to_owned()
        } else {
            "operator_evidence_partial".to_owned()
        },
        required: !required_set.is_empty(),
        evidence_attached,
        dispatch_completed: false,
        completion_basis: "none",
        required_recipients: required.iter().map(|name| (*name).to_owned()).collect(),
        recorded_recipients: recorded,
        missing_recipients: missing,
        note: if all_required_recipients_covered {
            profile.covered_note()
        } else {
            profile.uncovered_note()
        },
    })
}

pub(crate) fn absent_owner_recipient_names(act: &Act) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut recipients = Vec::new();
    for attendee in &act.attendees {
        if attendee.presence != PresenceMode::Absent {
            continue;
        }
        let name = attendee.name.trim();
        if name.is_empty() || !seen.insert(name.to_owned()) {
            continue;
        }
        recipients.push(name.to_owned());
    }
    recipients
}

fn convening_recipient_names(act: &Act) -> Vec<String> {
    let Some(convening) = &act.convening else {
        return Vec::new();
    };
    let mut seen = BTreeSet::new();
    let mut recipients = Vec::new();
    for recipient in &convening.recipients {
        let name = recipient.name.trim();
        if name.is_empty() || !seen.insert(name.to_owned()) {
            continue;
        }
        recipients.push(name.to_owned());
    }
    recipients
}
