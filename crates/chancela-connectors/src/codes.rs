//! The stable machine vocabulary for connector failures a client must translate.
//!
//! # Why this module exists
//!
//! Four of the eight connector protocols — S3, SFTP, SMB and FTPS — are behind a Cargo feature
//! (see this crate's `[features]` table). A build that does not enable one still *parses and
//! validates* a target of that kind: [`crate::TargetConfig`] is deliberately ungated, so an
//! operator's configuration never becomes unreadable because of how the binary was compiled.
//! What such a build cannot do is dial it.
//!
//! That gap has exactly one acceptable behaviour: refuse, loudly, naming the transport. It must
//! never fall back to another target, never silently succeed, and never report a backup as taken.
//! The house rule is reject-never-silently-transform, and a backup destination that quietly
//! no-ops is the worst possible version of that failure — the operator learns it during a
//! restore.
//!
//! # The rules these constants obey
//!
//! Same as `chancela-api`'s `provider_probe_codes`, and for the same reason: the wire sentence is
//! English and stable, and the client maps a stable identifier to a catalog key. Neither
//! `noLiteralUiCopy` nor `catalogLeakGate` can see a sentence the server writes, so a code is the
//! only thing that makes the message translatable.
//!
//! - **English, snake_case, never translated.** They are machine identifiers, like the
//!   `error_class` vocabulary that already rides the same DTO.
//! - **One code per distinct sentence, and no interpolation.** There is deliberately one code per
//!   transport rather than one code with a `{transport}` placeholder: a translator would
//!   otherwise have to drop a bare token into an inflected Portuguese sentence, which is how
//!   agreement breaks.
//! - **A code is append-only.** Renaming one silently changes what a client renders; deleting one
//!   makes an older client's translation dead. Add, do not edit.
//!
//! [`ALL_GATED_TRANSPORTS`] is the closed list the client-side guard reads. That guard is
//! `apps/web/src/i18n/connectorErrorCodes.test.ts`: it parses this file, resolves each listed
//! variant through [`GatedTransport::not_compiled_code`] to its `pub const`, and fails if any
//! resulting code has no catalog key — or if the map carries a key this file no longer emits.
//!
//! **That sentence used to be a claim rather than a fact.** This module was written to make the
//! failure translatable, and then nothing consumed the codes: `ConnectorOperations.tsx` rendered
//! the English [`crate::ConnectorError::message`] verbatim, so a Portuguese operator read
//! "this build was compiled without the s3 transport" in English. The list was closed, the guard
//! was not written, and the doc did not distinguish the two. Adding a code without its copy is
//! now a red test rather than a silent regression — which is the only reason this paragraph is
//! true.

use crate::ConnectorKind;

/// A protocol client that this crate compiles only when its Cargo feature is enabled.
///
/// Total by construction: every variant has a feature, a code and a [`ConnectorKind`], so
/// `build_connector`'s not-compiled arm cannot name a transport with no code. The four always-on
/// protocols (local, WebDAV, Microsoft Graph, Google Drive) are absent on purpose — they have no
/// heavy client to gate and can never produce this error.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GatedTransport {
    S3,
    Sftp,
    Smb,
    Ftps,
}

/// The closed list. A guard reads this to prove every code has a translation.
pub const ALL_GATED_TRANSPORTS: &[GatedTransport] = &[
    GatedTransport::S3,
    GatedTransport::Sftp,
    GatedTransport::Smb,
    GatedTransport::Ftps,
];

/// This build has no S3 client compiled in.
pub const TRANSPORT_NOT_COMPILED_S3: &str = "transport_not_compiled_s3";
/// This build has no SFTP client compiled in.
pub const TRANSPORT_NOT_COMPILED_SFTP: &str = "transport_not_compiled_sftp";
/// This build has no SMB client compiled in.
pub const TRANSPORT_NOT_COMPILED_SMB: &str = "transport_not_compiled_smb";
/// This build has no FTPS client compiled in.
pub const TRANSPORT_NOT_COMPILED_FTPS: &str = "transport_not_compiled_ftps";

impl GatedTransport {
    /// The connector kind this transport serves.
    pub const fn kind(self) -> ConnectorKind {
        match self {
            Self::S3 => ConnectorKind::S3,
            Self::Sftp => ConnectorKind::Sftp,
            Self::Smb => ConnectorKind::Smb,
            Self::Ftps => ConnectorKind::Ftps,
        }
    }

    /// The `chancela-connectors` Cargo feature that compiles this transport's client.
    ///
    /// Named in the error message so the operator is told what to rebuild, not merely that
    /// something is missing.
    pub const fn cargo_feature(self) -> &'static str {
        match self {
            Self::S3 => "s3",
            Self::Sftp => "sftp",
            Self::Smb => "smb",
            Self::Ftps => "ftps",
        }
    }

    /// The stable code a client maps to a translated sentence.
    pub const fn not_compiled_code(self) -> &'static str {
        match self {
            Self::S3 => TRANSPORT_NOT_COMPILED_S3,
            Self::Sftp => TRANSPORT_NOT_COMPILED_SFTP,
            Self::Smb => TRANSPORT_NOT_COMPILED_SMB,
            Self::Ftps => TRANSPORT_NOT_COMPILED_FTPS,
        }
    }

    /// Whether this build compiled the transport's client.
    ///
    /// The one place the `cfg`s are read, so every caller asks the same question the same way.
    pub const fn is_compiled(self) -> bool {
        match self {
            Self::S3 => cfg!(feature = "s3"),
            Self::Sftp => cfg!(feature = "sftp"),
            Self::Smb => cfg!(feature = "smb"),
            Self::Ftps => cfg!(feature = "ftps"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_gated_transport_has_a_distinct_code_and_feature() {
        let mut codes: Vec<&str> = ALL_GATED_TRANSPORTS
            .iter()
            .map(|t| t.not_compiled_code())
            .collect();
        let count = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), count, "codes must be distinct");

        let mut features: Vec<&str> = ALL_GATED_TRANSPORTS
            .iter()
            .map(|t| t.cargo_feature())
            .collect();
        features.sort_unstable();
        features.dedup();
        assert_eq!(features.len(), count, "cargo features must be distinct");
    }

    #[test]
    fn codes_are_snake_case_ascii_identifiers() {
        for transport in ALL_GATED_TRANSPORTS {
            let code = transport.not_compiled_code();
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{code} must be a snake_case ascii identifier"
            );
        }
    }
}
