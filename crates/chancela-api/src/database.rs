use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use chancela_store::{StoreError, StoreOpenOptions};
use serde::Serialize;

/// Environment variable carrying a SQLCipher database passphrase directly.
pub const DB_KEY_ENV: &str = "CHANCELA_DB_KEY";
/// Environment variable pointing at a file containing the SQLCipher database passphrase.
pub const DB_KEY_FILE_ENV: &str = "CHANCELA_DB_KEY_FILE";
/// Environment variable selecting the database-key source class.
///
/// `operator` preserves the existing [`DB_KEY_ENV`] / [`DB_KEY_FILE_ENV`] behavior. A
/// `hardware_derived_fallback` request currently fails closed because this crate does not yet have
/// a hardware-bound key derivation provider.
pub const DB_KEY_SOURCE_ENV: &str = "CHANCELA_DB_KEY_SOURCE";

/// Where a database encryption key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseEncryptionKeySource {
    /// The key was read directly from [`DB_KEY_ENV`].
    #[serde(rename = "operator_env")]
    Env,
    /// The key was read from the file named by [`DB_KEY_FILE_ENV`].
    #[serde(rename = "operator_key_file")]
    File,
    /// The key was supplied by an embedding caller instead of the process environment.
    Programmatic,
    /// A future hardware-derived default/fallback key source.
    ///
    /// This is a status/config value only today: requesting it fails closed instead of deriving from
    /// a static application secret or another weak fallback.
    HardwareDerivedFallback,
}

impl DatabaseEncryptionKeySource {
    fn label(self) -> &'static str {
        match self {
            Self::Env => DB_KEY_ENV,
            Self::File => DB_KEY_FILE_ENV,
            Self::Programmatic => "programmatic database encryption key",
            Self::HardwareDerivedFallback => "hardware-derived database encryption key fallback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseEncryptionKeySourceRequest {
    Operator,
    HardwareDerivedFallback,
}

type ConfigResult<T> = Result<T, DatabaseEncryptionConfigError>;

/// Invalid database encryption configuration.
#[derive(Debug)]
pub enum DatabaseEncryptionConfigError {
    /// The key-source selector contained non-Unicode data.
    NonUnicodeKeySource,
    /// The key-source selector named a source class this build does not understand.
    UnsupportedKeySource {
        /// The operator-supplied selector value.
        value: String,
    },
    /// Hardware-bound default/fallback key derivation was requested, but no provider is wired.
    HardwareDerivedFallbackUnavailable,
    /// Both supported key sources were configured. Only one may be used.
    AmbiguousSources,
    /// The direct key env var contained non-Unicode data.
    NonUnicodeKey,
    /// A configured key source resolved to an empty key.
    EmptyKey {
        /// The source that supplied the empty key.
        source: DatabaseEncryptionKeySource,
    },
    /// The key-file env var was present but empty.
    EmptyKeyFilePath,
    /// The configured key file could not be read as UTF-8 text.
    ReadKeyFile {
        /// The path configured by [`DB_KEY_FILE_ENV`].
        path: PathBuf,
        /// The filesystem or UTF-8 error returned while reading the key file.
        source: std::io::Error,
    },
}

impl fmt::Display for DatabaseEncryptionConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUnicodeKeySource => write!(
                f,
                "{DB_KEY_SOURCE_ENV} contains non-Unicode data; database key-source selectors must \
                 be UTF-8"
            ),
            Self::UnsupportedKeySource { value } => write!(
                f,
                "{DB_KEY_SOURCE_ENV}={value:?} is not supported; use operator or \
                 hardware_derived_fallback"
            ),
            Self::HardwareDerivedFallbackUnavailable => write!(
                f,
                "hardware-derived database key fallback was requested via {DB_KEY_SOURCE_ENV}, but \
                 no hardware-bound key derivation provider is implemented; startup fails closed \
                 instead of using a static or weak database key"
            ),
            Self::AmbiguousSources => write!(
                f,
                "{DB_KEY_ENV} and {DB_KEY_FILE_ENV} are both set; configure only one database \
                 encryption key source"
            ),
            Self::NonUnicodeKey => write!(
                f,
                "{DB_KEY_ENV} contains non-Unicode data; database encryption keys must be UTF-8"
            ),
            Self::EmptyKey { source } => write!(
                f,
                "{} did not provide a non-empty database encryption key",
                source.label()
            ),
            Self::EmptyKeyFilePath => write!(f, "{DB_KEY_FILE_ENV} is set but empty"),
            Self::ReadKeyFile { path, source } => write!(
                f,
                "failed to read database encryption key file configured by {DB_KEY_FILE_ENV} at \
                 {}: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for DatabaseEncryptionConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadKeyFile { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Database encryption settings resolved for store startup.
///
/// The default is plaintext SQLite. When a key is present, [`crate::AppState::try_with_data_dir`]
/// opens the store through `StoreOpenOptions` and fails closed unless this crate was built with the
/// `sqlcipher` feature.
#[derive(Clone, Default)]
pub struct DatabaseEncryptionConfig {
    key: Option<String>,
    source: Option<DatabaseEncryptionKeySource>,
}

impl fmt::Debug for DatabaseEncryptionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseEncryptionConfig")
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .field("source", &self.source)
            .finish()
    }
}

impl DatabaseEncryptionConfig {
    /// Plaintext SQLite store configuration.
    pub fn plaintext() -> Self {
        Self::default()
    }

    /// Build a database encryption config from a caller-supplied key.
    pub fn with_key(key: impl Into<String>) -> ConfigResult<Self> {
        let key = normalize_key(key.into(), DatabaseEncryptionKeySource::Programmatic)?;
        Ok(Self {
            key: Some(key),
            source: Some(DatabaseEncryptionKeySource::Programmatic),
        })
    }

    /// Resolve database encryption settings from [`DB_KEY_SOURCE_ENV`], [`DB_KEY_ENV`], and
    /// [`DB_KEY_FILE_ENV`].
    pub fn from_env() -> ConfigResult<Self> {
        let key_source_request = key_source_request_from_env()?;
        if key_source_request == DatabaseEncryptionKeySourceRequest::HardwareDerivedFallback {
            return Self::from_sources_for_request(None, None, key_source_request);
        }

        let key = match std::env::var_os(DB_KEY_ENV) {
            Some(raw) => Some(os_secret_to_string(raw)?),
            None => None,
        };
        let key_file = std::env::var_os(DB_KEY_FILE_ENV).map(PathBuf::from);
        Self::from_sources(key, key_file)
    }

    /// Whether a database encryption key was configured.
    pub fn is_configured(&self) -> bool {
        self.key.is_some()
    }

    /// Non-secret key-source classification for startup/status reporting.
    pub fn key_source(&self) -> Option<DatabaseEncryptionKeySource> {
        self.source
    }

    /// Convert this resolved encryption config into durable-store open options.
    ///
    /// The returned options redact key material in `Debug`; callers must still avoid logging the
    /// original environment variables or file contents.
    pub fn store_open_options(&self) -> StoreOpenOptions {
        match &self.key {
            Some(key) => StoreOpenOptions::new().with_encryption_key(key.clone()),
            None => StoreOpenOptions::default(),
        }
    }

    fn from_sources(key: Option<String>, key_file: Option<PathBuf>) -> ConfigResult<Self> {
        Self::from_sources_for_request(key, key_file, DatabaseEncryptionKeySourceRequest::Operator)
    }

    fn from_sources_for_request(
        key: Option<String>,
        key_file: Option<PathBuf>,
        key_source_request: DatabaseEncryptionKeySourceRequest,
    ) -> ConfigResult<Self> {
        if key_source_request == DatabaseEncryptionKeySourceRequest::HardwareDerivedFallback {
            return Err(DatabaseEncryptionConfigError::HardwareDerivedFallbackUnavailable);
        }

        match (key, key_file) {
            (None, None) => Ok(Self::plaintext()),
            (Some(_), Some(_)) => Err(DatabaseEncryptionConfigError::AmbiguousSources),
            (Some(raw), None) => Ok(Self {
                key: Some(normalize_key(raw, DatabaseEncryptionKeySource::Env)?),
                source: Some(DatabaseEncryptionKeySource::Env),
            }),
            (None, Some(path)) => {
                if path.as_os_str().is_empty() {
                    return Err(DatabaseEncryptionConfigError::EmptyKeyFilePath);
                }
                let raw = std::fs::read_to_string(&path).map_err(|source| {
                    DatabaseEncryptionConfigError::ReadKeyFile {
                        path: path.clone(),
                        source,
                    }
                })?;
                Ok(Self {
                    key: Some(normalize_key(raw, DatabaseEncryptionKeySource::File)?),
                    source: Some(DatabaseEncryptionKeySource::File),
                })
            }
        }
    }
}

/// Startup errors that must prevent a server from continuing with a misleading plaintext or
/// in-memory store.
#[derive(Debug)]
pub enum AppStateInitError {
    /// The key env/file configuration is invalid.
    DatabaseEncryption(DatabaseEncryptionConfigError),
    /// A key was configured, but there is no durable database to encrypt.
    DatabaseEncryptionRequiresDataDir,
    /// A key was configured without compiling SQLCipher support into this crate.
    SqlcipherFeatureUnavailable,
    /// The encrypted store could not be opened.
    StoreOpen {
        /// The data directory whose database was being opened.
        data_dir: PathBuf,
        /// The store error. SQLCipher key material is never included by `chancela-store`.
        source: StoreError,
    },
    /// The encrypted store opened but its durable state could not be loaded.
    StoreLoad {
        /// The data directory whose database was being loaded.
        data_dir: PathBuf,
        /// The store load error.
        source: StoreError,
    },
}

impl fmt::Display for AppStateInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseEncryption(err) => err.fmt(f),
            Self::DatabaseEncryptionRequiresDataDir => write!(
                f,
                "database encryption was configured, but no durable data directory was resolved; \
                 set CHANCELA_DATA_DIR when using {DB_KEY_ENV} or {DB_KEY_FILE_ENV}"
            ),
            Self::SqlcipherFeatureUnavailable => write!(
                f,
                "database encryption was configured, but this build was not compiled with the \
                 sqlcipher feature"
            ),
            Self::StoreOpen { data_dir, source } => write!(
                f,
                "failed to open encrypted durable store at {}: {source}",
                data_dir.display()
            ),
            Self::StoreLoad { data_dir, source } => write!(
                f,
                "failed to load encrypted durable store at {}: {source}",
                data_dir.display()
            ),
        }
    }
}

impl std::error::Error for AppStateInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DatabaseEncryption(err) => Some(err),
            Self::StoreOpen { source, .. } | Self::StoreLoad { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<DatabaseEncryptionConfigError> for AppStateInitError {
    fn from(err: DatabaseEncryptionConfigError) -> Self {
        Self::DatabaseEncryption(err)
    }
}

fn os_secret_to_string(raw: OsString) -> ConfigResult<String> {
    raw.into_string()
        .map_err(|_| DatabaseEncryptionConfigError::NonUnicodeKey)
}

fn key_source_request_from_env() -> ConfigResult<DatabaseEncryptionKeySourceRequest> {
    let Some(raw) = std::env::var_os(DB_KEY_SOURCE_ENV) else {
        return Ok(DatabaseEncryptionKeySourceRequest::Operator);
    };
    let value = raw
        .into_string()
        .map_err(|_| DatabaseEncryptionConfigError::NonUnicodeKeySource)?;
    parse_key_source_request(&value)
}

fn parse_key_source_request(value: &str) -> ConfigResult<DatabaseEncryptionKeySourceRequest> {
    let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
    match normalized.as_str() {
        "" | "operator" | "operator_env" | "operator_key" | "operator_key_file" | "env"
        | "file" => Ok(DatabaseEncryptionKeySourceRequest::Operator),
        "hardware" | "hardware_bound" | "hardware_derived" | "hardware_derived_fallback" => {
            Ok(DatabaseEncryptionKeySourceRequest::HardwareDerivedFallback)
        }
        _ => Err(DatabaseEncryptionConfigError::UnsupportedKeySource {
            value: value.to_owned(),
        }),
    }
}

fn normalize_key(raw: String, source: DatabaseEncryptionKeySource) -> ConfigResult<String> {
    if raw.trim().is_empty() {
        return Err(DatabaseEncryptionConfigError::EmptyKey { source });
    }
    Ok(raw.trim_end_matches(&['\r', '\n'][..]).to_owned())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let seq = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "chancela-db-encryption-{}-{seq}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn no_key_config_preserves_plaintext_store_startup() {
        let config =
            DatabaseEncryptionConfig::from_sources(None, None).expect("default config parses");
        assert!(!config.is_configured());
        assert_eq!(config.key_source(), None);

        let dir = TempDir::new();
        let state = match crate::AppState::try_with_data_dir(dir.path().to_path_buf(), config) {
            Ok(state) => state,
            Err(err) => panic!("plaintext data-dir startup should not fail: {err}"),
        };

        assert!(state.store.is_some());
        assert!(!state.database_encryption_configured);
        let db_bytes = std::fs::read(dir.path().join(chancela_store::DB_FILE)).expect("read db");
        assert!(
            db_bytes.starts_with(b"SQLite format 3"),
            "default no-key startup must keep the existing plaintext SQLite format"
        );
    }

    #[test]
    fn rejects_ambiguous_key_sources() {
        let file = PathBuf::from("db.key");
        let err = DatabaseEncryptionConfig::from_sources(Some("secret".to_owned()), Some(file))
            .expect_err("both key sources must be invalid");
        assert!(matches!(
            err,
            DatabaseEncryptionConfigError::AmbiguousSources
        ));
    }

    #[test]
    fn rejects_empty_direct_key() {
        let err = DatabaseEncryptionConfig::from_sources(Some(" \n\t ".to_owned()), None)
            .expect_err("empty key must be invalid");
        assert!(matches!(
            err,
            DatabaseEncryptionConfigError::EmptyKey {
                source: DatabaseEncryptionKeySource::Env
            }
        ));
    }

    #[test]
    fn rejects_empty_key_file() {
        let dir = TempDir::new();
        let key_file = dir.path().join("db.key");
        std::fs::write(&key_file, "\n\n").expect("write key file");

        let err = DatabaseEncryptionConfig::from_sources(None, Some(key_file))
            .expect_err("empty key file must be invalid");
        assert!(matches!(
            err,
            DatabaseEncryptionConfigError::EmptyKey {
                source: DatabaseEncryptionKeySource::File
            }
        ));
    }

    #[test]
    fn rejects_unreadable_key_file() {
        let dir = TempDir::new();
        let missing = dir.path().join("missing.key");

        let err = DatabaseEncryptionConfig::from_sources(None, Some(missing))
            .expect_err("missing key file must be invalid");
        assert!(matches!(
            err,
            DatabaseEncryptionConfigError::ReadKeyFile { .. }
        ));
    }

    #[test]
    fn key_file_trailing_newline_is_accepted() {
        let dir = TempDir::new();
        let key_file = dir.path().join("db.key");
        std::fs::write(&key_file, "correct horse battery staple\n").expect("write key file");

        let config =
            DatabaseEncryptionConfig::from_sources(None, Some(key_file)).expect("read key file");

        assert!(config.is_configured());
        assert_eq!(config.key_source(), Some(DatabaseEncryptionKeySource::File));
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("correct horse battery staple"));
    }

    #[test]
    fn direct_key_records_operator_env_source_without_leaking_key() {
        let config = DatabaseEncryptionConfig::from_sources(Some("env secret".to_owned()), None)
            .expect("env key config");

        assert!(config.is_configured());
        assert_eq!(config.key_source(), Some(DatabaseEncryptionKeySource::Env));
        let debug = format!("{config:?}");
        assert!(debug.contains("Env"));
        assert!(!debug.contains("env secret"));
    }

    #[test]
    fn programmatic_key_records_programmatic_source_without_leaking_key() {
        let config = DatabaseEncryptionConfig::with_key("programmatic secret").expect("valid key");

        assert_eq!(
            config.key_source(),
            Some(DatabaseEncryptionKeySource::Programmatic)
        );
        let debug = format!("{config:?}");
        assert!(debug.contains("Programmatic"));
        assert!(!debug.contains("programmatic secret"));
    }

    #[test]
    fn hardware_derived_fallback_request_fails_closed_without_static_key() {
        let err = DatabaseEncryptionConfig::from_sources_for_request(
            Some("operator secret should not matter".to_owned()),
            None,
            DatabaseEncryptionKeySourceRequest::HardwareDerivedFallback,
        )
        .expect_err("hardware fallback is not silently substituted");

        assert!(matches!(
            err,
            DatabaseEncryptionConfigError::HardwareDerivedFallbackUnavailable
        ));
        let message = err.to_string();
        assert!(message.contains(DB_KEY_SOURCE_ENV));
        assert!(message.contains("fails closed"));
        assert!(!message.contains("operator secret"));
    }

    #[test]
    fn unsupported_key_source_selector_is_rejected() {
        let err = parse_key_source_request("static-test-key")
            .expect_err("unsupported key-source selectors fail closed");

        assert!(matches!(
            err,
            DatabaseEncryptionConfigError::UnsupportedKeySource { .. }
        ));
        assert!(err.to_string().contains(DB_KEY_SOURCE_ENV));
    }

    #[cfg(not(feature = "sqlcipher"))]
    #[test]
    fn configured_key_fails_closed_without_sqlcipher_feature() {
        let dir = TempDir::new();
        let config =
            DatabaseEncryptionConfig::with_key("correct horse battery staple").expect("valid key");

        let err = match crate::AppState::try_with_data_dir(dir.path().to_path_buf(), config) {
            Ok(_) => panic!("configured key must fail without sqlcipher feature"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            AppStateInitError::SqlcipherFeatureUnavailable
        ));
        let message = err.to_string();
        assert!(!message.contains("correct horse battery staple"));
        assert!(
            !dir.path().join(chancela_store::DB_FILE).exists(),
            "no-feature encrypted startup must not create a plaintext database"
        );
    }

    #[cfg(not(feature = "sqlcipher"))]
    #[test]
    fn configured_key_against_plaintext_store_reports_migration_guard() {
        let dir = TempDir::new();
        chancela_store::Store::open(dir.path()).expect("create existing plaintext store");
        let config =
            DatabaseEncryptionConfig::with_key("correct horse battery staple").expect("valid key");

        let err = match crate::AppState::try_with_data_dir(dir.path().to_path_buf(), config) {
            Ok(_) => panic!("configured key must not migrate a plaintext store in place"),
            Err(err) => err,
        };

        let message = err.to_string();
        match err {
            AppStateInitError::StoreOpen { source, .. } => {
                assert!(
                    matches!(
                        source,
                        StoreError::PlaintextEncryptionMigrationUnsupported { .. }
                    ),
                    "got {source:?}"
                );
            }
            other => panic!("expected store-open migration guard, got {other:?}"),
        }
        assert!(!message.contains("correct horse battery staple"));
        assert!(message.contains("refusing to rewrite plaintext SQLite database"));
        assert!(message.contains("backup/export-restore"));
        assert!(message.contains("verify the restored ledger"));
    }
}
