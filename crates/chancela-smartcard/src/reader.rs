//! PC/SC reader detection.
//!
//! [`detect`] is the acceptance-critical entry point: on a box with no reader,
//! a stopped Smart Card service, or no PC/SC at all, it returns a clean result
//! and **never panics** (plan §3, e9 smoke test). Zero readers is `Ok(vec![])`;
//! an absent resource manager is a typed [`SmartcardError::PcscUnavailable`].

use crate::error::SmartcardError;

/// A detected PC/SC reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderInfo {
    /// The reader's PC/SC name (e.g. `"ACS ACR39U ICC Reader 0"`).
    pub name: String,
}

/// The reader-enumeration boundary, so detection logic is testable without
/// PC/SC (a fake `CardReaders` can return canned lists).
pub trait CardReaders {
    /// List the connected readers.
    ///
    /// # Errors
    /// [`SmartcardError::PcscUnavailable`] if the resource manager is not
    /// running. An empty list (no readers connected) is `Ok(vec![])`, not an
    /// error.
    fn list_readers(&self) -> Result<Vec<ReaderInfo>, SmartcardError>;
}

/// Real PC/SC reader enumeration over the `pcsc` crate.
#[derive(Debug, Default, Clone, Copy)]
pub struct PcscReaders;

impl PcscReaders {
    /// Construct the PC/SC reader source.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl CardReaders for PcscReaders {
    fn list_readers(&self) -> Result<Vec<ReaderInfo>, SmartcardError> {
        use pcsc::{Context, Error, Scope};

        let ctx = match Context::establish(Scope::User) {
            Ok(ctx) => ctx,
            // The service being absent/stopped is expected on CI and on desktops
            // without the middleware — report it cleanly, do not panic.
            Err(Error::NoService | Error::ServiceStopped) => {
                return Err(SmartcardError::PcscUnavailable(
                    "smart card resource manager is not running".to_owned(),
                ));
            }
            Err(e) => return Err(SmartcardError::PcscUnavailable(e.to_string())),
        };

        match ctx.list_readers_owned() {
            Ok(names) => Ok(names
                .into_iter()
                .map(|c| ReaderInfo {
                    name: c.to_string_lossy().into_owned(),
                })
                .collect()),
            // Some PC/SC stacks return this instead of an empty list.
            Err(Error::NoReadersAvailable) => Ok(Vec::new()),
            Err(Error::NoService | Error::ServiceStopped) => Err(SmartcardError::PcscUnavailable(
                "smart card resource manager stopped".to_owned(),
            )),
            Err(e) => Err(SmartcardError::Pcsc(e.to_string())),
        }
    }
}

/// Detect connected card readers via PC/SC.
///
/// Convenience wrapper over [`PcscReaders`]. Returns `Ok(vec![])` when the
/// service is running but no reader is attached, and
/// [`SmartcardError::PcscUnavailable`] when PC/SC itself is unavailable —
/// **never panics** (acceptance criterion for the e9 smoke test on this box).
///
/// # Errors
/// [`SmartcardError::PcscUnavailable`] / [`SmartcardError::Pcsc`] as above.
pub fn detect() -> Result<Vec<ReaderInfo>, SmartcardError> {
    PcscReaders::new().list_readers()
}
