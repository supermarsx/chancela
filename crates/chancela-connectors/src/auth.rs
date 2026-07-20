use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use zeroize::Zeroize;

use crate::{ConnectorError, ErrorClass};

/// A secret that zeroizes its owned buffer and never exposes it through
/// `Debug` or `Display`.
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Result<Self, ConnectorError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ConnectorError::new(
                ErrorClass::Authentication,
                "credential reference resolved to an empty value",
            ));
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub trait SecretProvider: Send + Sync {
    fn resolve(&self, reference: &str) -> Result<SecretValue, ConnectorError>;
}

#[derive(Debug, Default)]
pub struct EnvSecretProvider;

pub const SECRET_PREFIX: &str = "CHANCELA_CONNECTOR_SECRET_";
pub const SECRETS_DIR_ENV: &str = "CHANCELA_CONNECTOR_SECRETS_DIR";

impl SecretProvider for EnvSecretProvider {
    fn resolve(&self, reference: &str) -> Result<SecretValue, ConnectorError> {
        validate_reference(reference)?;
        let value = match std::env::var(reference) {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => {
                let file_reference = format!("{reference}_FILE");
                let configured_path = std::env::var(&file_reference).map_err(|_| {
                    ConnectorError::new(
                        ErrorClass::Authentication,
                        format!("credential reference {reference} is unavailable"),
                    )
                })?;
                let path = confined_secret_file(&configured_path)?;
                let metadata = std::fs::metadata(&path).map_err(|_| {
                    ConnectorError::new(
                        ErrorClass::Authentication,
                        format!("credential file for {reference} is unavailable"),
                    )
                })?;
                if !metadata.is_file() || metadata.len() > 64 * 1024 {
                    return Err(ConnectorError::new(
                        ErrorClass::Authentication,
                        format!("credential file for {reference} is invalid"),
                    ));
                }
                let bytes = std::fs::read(path).map_err(|_| {
                    ConnectorError::new(
                        ErrorClass::Authentication,
                        format!("credential file for {reference} is unreadable"),
                    )
                })?;
                let value = String::from_utf8(bytes).map_err(|_| {
                    ConnectorError::new(
                        ErrorClass::Authentication,
                        format!("credential file for {reference} is not UTF-8"),
                    )
                })?;
                value.trim_end_matches(['\r', '\n']).to_owned()
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConnectorError::new(
                    ErrorClass::Authentication,
                    format!("credential reference {reference} is invalid"),
                ));
            }
        };
        SecretValue::new(value)
    }
}

#[derive(Debug, Default)]
pub struct InMemorySecretProvider {
    values: RwLock<BTreeMap<String, String>>,
}

impl InMemorySecretProvider {
    pub fn insert(&self, reference: impl Into<String>, value: impl Into<String>) {
        self.values
            .write()
            .expect("in-memory secret provider lock poisoned")
            .insert(reference.into(), value.into());
    }
}

impl SecretProvider for InMemorySecretProvider {
    fn resolve(&self, reference: &str) -> Result<SecretValue, ConnectorError> {
        validate_reference(reference)?;
        let values = self
            .values
            .read()
            .map_err(|_| ConnectorError::configuration("secret provider lock poisoned"))?;
        SecretValue::new(values.get(reference).cloned().ok_or_else(|| {
            ConnectorError::new(
                ErrorClass::Authentication,
                format!("credential reference {reference} is unavailable"),
            )
        })?)
    }
}

pub(crate) fn validate_reference(reference: &str) -> Result<(), ConnectorError> {
    let suffix = reference.strip_prefix(SECRET_PREFIX).unwrap_or_default();
    let valid = !suffix.is_empty()
        && reference.len() <= 128
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
    if valid {
        Ok(())
    } else {
        Err(ConnectorError::configuration(format!(
            "credential references must start with {SECRET_PREFIX} and contain only A-Z, 0-9, and underscore"
        )))
    }
}

fn confined_secret_file(configured_path: &str) -> Result<PathBuf, ConnectorError> {
    let base_configured = std::env::var(SECRETS_DIR_ENV).map_err(|_| {
        ConnectorError::new(
            ErrorClass::Authentication,
            format!("{SECRETS_DIR_ENV} is required for file-backed connector secrets"),
        )
    })?;
    let configured_base = PathBuf::from(base_configured);
    let base_path = if configured_base.is_absolute() {
        configured_base
    } else {
        std::env::current_dir()
            .map_err(|_| {
                ConnectorError::new(
                    ErrorClass::Authentication,
                    "connector secrets directory is unavailable",
                )
            })?
            .join(configured_base)
    };
    let base_metadata = std::fs::symlink_metadata(&base_path).map_err(|_| {
        ConnectorError::new(
            ErrorClass::Authentication,
            "connector secrets directory is unavailable",
        )
    })?;
    if !base_metadata.is_dir() || base_metadata.file_type().is_symlink() {
        return Err(ConnectorError::new(
            ErrorClass::Authentication,
            "connector secrets directory is invalid",
        ));
    }
    let base = std::fs::canonicalize(&base_path).map_err(|_| {
        ConnectorError::new(
            ErrorClass::Authentication,
            "connector secrets directory is unavailable",
        )
    })?;
    let configured = PathBuf::from(configured_path);
    let candidate = if configured.is_absolute() {
        configured
    } else {
        base_path.join(configured)
    };
    // Inspect the lexical operator-supplied path first. On Windows, canonical paths carry an
    // extended-length prefix, so comparing a canonical base to a non-canonical absolute child
    // would reject a legitimate confined file before the final canonical containment check.
    reject_symlink_components(&base_path, &candidate)?;
    let canonical = std::fs::canonicalize(&candidate).map_err(|_| {
        ConnectorError::new(
            ErrorClass::Authentication,
            "connector credential file is unavailable",
        )
    })?;
    if !canonical.starts_with(&base) {
        return Err(ConnectorError::new(
            ErrorClass::Authentication,
            "connector credential file escapes the configured secrets directory",
        ));
    }
    Ok(canonical)
}

fn reject_symlink_components(base: &Path, candidate: &Path) -> Result<(), ConnectorError> {
    let relative = candidate.strip_prefix(base).map_err(|_| {
        ConnectorError::new(
            ErrorClass::Authentication,
            "connector credential file escapes the configured secrets directory",
        )
    })?;
    let mut current = base.to_path_buf();
    for component in relative.components() {
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current).map_err(|_| {
            ConnectorError::new(
                ErrorClass::Authentication,
                "connector credential file is unavailable",
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ConnectorError::new(
                ErrorClass::Authentication,
                "connector credential file must not traverse symbolic links",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn set_env(key: &str, value: impl AsRef<std::ffi::OsStr>) {
        // SAFETY: connector environment tests serialize all mutations through ENV_LOCK.
        unsafe { std::env::set_var(key, value) };
    }

    fn clear_env(key: &str) {
        // SAFETY: connector environment tests serialize all mutations through ENV_LOCK.
        unsafe { std::env::remove_var(key) };
    }

    #[test]
    fn debug_never_exposes_secret() {
        let secret = SecretValue::new("top-secret-token").expect("secret");
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "SecretValue([REDACTED])");
        assert!(!rendered.contains("top-secret-token"));
    }

    #[test]
    fn credential_reference_namespace_is_strict() {
        assert!(validate_reference("CHANCELA_CONNECTOR_SECRET_GRAPH_TOKEN").is_ok());
        for invalid in [
            "GRAPH_TOKEN",
            "CHANCELA_CONNECTOR_SECRET_",
            "CHANCELA_CONNECTOR_SECRET_lowercase",
            "CHANCELA_CONNECTOR_SECRET_DASH-NAME",
        ] {
            assert!(validate_reference(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn file_backed_secret_is_confined_to_dedicated_directory() {
        let _guard = ENV_LOCK.lock().expect("environment lock");
        let fixture =
            std::env::temp_dir().join(format!("chancela-secret-{}", uuid::Uuid::new_v4()));
        let secrets = fixture.join("secrets");
        std::fs::create_dir_all(&secrets).expect("create secrets fixture");
        std::fs::write(secrets.join("inside"), b"inside-secret\n").expect("write secret");
        std::fs::write(fixture.join("outside"), b"outside-secret\n").expect("write outside");
        let reference = "CHANCELA_CONNECTOR_SECRET_TEST";
        let file_reference = format!("{reference}_FILE");
        clear_env(reference);
        set_env(SECRETS_DIR_ENV, &secrets);

        set_env(&file_reference, "../outside");
        assert!(EnvSecretProvider.resolve(reference).is_err());

        set_env(&file_reference, "inside");
        let secret = EnvSecretProvider
            .resolve(reference)
            .expect("confined secret");
        assert_eq!(secret.expose(), "inside-secret");

        clear_env(reference);
        clear_env(&file_reference);
        clear_env(SECRETS_DIR_ENV);
        let _ = std::fs::remove_dir_all(fixture);
    }

    #[cfg(unix)]
    #[test]
    fn file_backed_secret_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let _guard = ENV_LOCK.lock().expect("environment lock");
        let fixture =
            std::env::temp_dir().join(format!("chancela-secret-{}", uuid::Uuid::new_v4()));
        let secrets = fixture.join("secrets");
        std::fs::create_dir_all(&secrets).expect("create secrets fixture");
        std::fs::write(fixture.join("outside"), b"outside-secret\n").expect("write outside");
        symlink(fixture.join("outside"), secrets.join("linked")).expect("create symlink");
        let reference = "CHANCELA_CONNECTOR_SECRET_TEST";
        let file_reference = format!("{reference}_FILE");
        clear_env(reference);
        set_env(SECRETS_DIR_ENV, &secrets);
        set_env(&file_reference, "linked");

        assert!(EnvSecretProvider.resolve(reference).is_err());

        clear_env(reference);
        clear_env(&file_reference);
        clear_env(SECRETS_DIR_ENV);
        let _ = std::fs::remove_dir_all(fixture);
    }
}
