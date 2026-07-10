use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use chancela_api::{
    DatabaseEncryptionConfig, DatabaseEncryptionConfigError, DB_KEY_ENV, DB_KEY_FILE_ENV,
};
use serde::{Deserialize, Serialize};

pub(crate) const ALLOW_PLAINTEXT_DB_ENV: &str = "CHANCELA_DESKTOP_ALLOW_PLAINTEXT_DB";

const KEY_FILE_NAME: &str = "database-key.current-user-dpapi.json";
const KEY_FILE_FORMAT: &str = "chancela-desktop-sqlcipher-key/v1";
const GENERATED_KEY_BYTES: usize = 32;

#[cfg(windows)]
const WINDOWS_DPAPI_PROVIDER: &str = "windows-current-user-dpapi";

#[derive(Debug)]
pub(crate) enum DesktopDatabaseEncryptionError {
    Config(DatabaseEncryptionConfigError),
    SqlcipherUnavailable,
    #[cfg_attr(windows, allow(dead_code))]
    ProviderUnavailable {
        platform: &'static str,
    },
    Io {
        action: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    InvalidEnvelope {
        path: PathBuf,
        reason: String,
    },
    Provider {
        provider: &'static str,
        operation: &'static str,
        source: std::io::Error,
    },
    Random(getrandom::Error),
}

impl fmt::Display for DesktopDatabaseEncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(err) => err.fmt(f),
            Self::SqlcipherUnavailable => write!(
                f,
                "desktop database encryption requires a SQLCipher-enabled build; rebuild \
                 chancela-desktop with --features sqlcipher, or set \
                 {ALLOW_PLAINTEXT_DB_ENV}=1 only for an explicit local development/no-sqlcipher \
                 run"
            ),
            Self::ProviderUnavailable { platform } => write!(
                f,
                "no OS-backed desktop database-key provider is available for {platform}; configure \
                 {DB_KEY_FILE_ENV} or {DB_KEY_ENV}, or run on a platform with a supported \
                 current-user secret provider"
            ),
            Self::Io {
                action,
                path,
                source,
            } => write!(f, "failed to {action} {}: {source}", path.display()),
            Self::Json { path, source } => write!(
                f,
                "failed to parse protected database-key file {}: {source}",
                path.display()
            ),
            Self::InvalidEnvelope { path, reason } => write!(
                f,
                "protected database-key file {} is invalid: {reason}",
                path.display()
            ),
            Self::Provider {
                provider,
                operation,
                source,
            } => write!(
                f,
                "database-key provider {provider} failed to {operation} the SQLCipher key: {source}"
            ),
            Self::Random(err) => write!(f, "failed to generate a random SQLCipher key: {err}"),
        }
    }
}

impl std::error::Error for DesktopDatabaseEncryptionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(err) => Some(err),
            Self::Io { source, .. } | Self::Provider { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Random(err) => Some(err),
            Self::SqlcipherUnavailable
            | Self::ProviderUnavailable { .. }
            | Self::InvalidEnvelope { .. } => None,
        }
    }
}

impl From<DatabaseEncryptionConfigError> for DesktopDatabaseEncryptionError {
    fn from(err: DatabaseEncryptionConfigError) -> Self {
        Self::Config(err)
    }
}

#[derive(Debug)]
pub(crate) struct ResolvedDatabaseEncryption {
    pub(crate) config: DatabaseEncryptionConfig,
    pub(crate) mode: ResolvedDatabaseEncryptionMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolvedDatabaseEncryptionMode {
    EnvOverride,
    #[cfg_attr(not(feature = "sqlcipher"), allow(dead_code))]
    OsProtectedKeyFile {
        provider: &'static str,
        path: PathBuf,
        created: bool,
    },
    ExplicitPlaintextFallback,
}

pub(crate) fn resolve_database_encryption_config(
    data_dir: &Path,
) -> Result<ResolvedDatabaseEncryption, DesktopDatabaseEncryptionError> {
    resolve_database_encryption_config_with_plaintext_permission(
        data_dir,
        plaintext_fallback_allowed(),
    )
}

fn resolve_database_encryption_config_with_plaintext_permission(
    data_dir: &Path,
    allow_plaintext_without_sqlcipher: bool,
) -> Result<ResolvedDatabaseEncryption, DesktopDatabaseEncryptionError> {
    let env_config = DatabaseEncryptionConfig::from_env()?;
    if env_config.is_configured() {
        if cfg!(feature = "sqlcipher") {
            return Ok(ResolvedDatabaseEncryption {
                config: env_config,
                mode: ResolvedDatabaseEncryptionMode::EnvOverride,
            });
        }
        return Err(DesktopDatabaseEncryptionError::SqlcipherUnavailable);
    }

    resolve_default_database_encryption_config(data_dir, allow_plaintext_without_sqlcipher)
}

#[cfg(feature = "sqlcipher")]
fn resolve_default_database_encryption_config(
    data_dir: &Path,
    _allow_plaintext_without_sqlcipher: bool,
) -> Result<ResolvedDatabaseEncryption, DesktopDatabaseEncryptionError> {
    let protected_key_file = default_protected_key_file(data_dir);
    let loaded = load_or_create_platform_key(&protected_key_file)?;
    Ok(ResolvedDatabaseEncryption {
        config: DatabaseEncryptionConfig::with_key(loaded.key)?,
        mode: ResolvedDatabaseEncryptionMode::OsProtectedKeyFile {
            provider: loaded.provider,
            path: protected_key_file,
            created: loaded.created,
        },
    })
}

#[cfg(not(feature = "sqlcipher"))]
fn resolve_default_database_encryption_config(
    _data_dir: &Path,
    allow_plaintext_without_sqlcipher: bool,
) -> Result<ResolvedDatabaseEncryption, DesktopDatabaseEncryptionError> {
    if allow_plaintext_without_sqlcipher {
        return Ok(ResolvedDatabaseEncryption {
            config: DatabaseEncryptionConfig::plaintext(),
            mode: ResolvedDatabaseEncryptionMode::ExplicitPlaintextFallback,
        });
    }
    Err(DesktopDatabaseEncryptionError::SqlcipherUnavailable)
}

fn plaintext_fallback_allowed() -> bool {
    std::env::var(ALLOW_PLAINTEXT_DB_ENV)
        .map(|raw| truthy_env_value(&raw))
        .unwrap_or(false)
}

fn truthy_env_value(raw: &str) -> bool {
    let normalized = raw.trim().to_ascii_lowercase();
    !(normalized.is_empty()
        || normalized == "0"
        || normalized == "false"
        || normalized == "off"
        || normalized == "no")
}

#[cfg_attr(not(feature = "sqlcipher"), allow(dead_code))]
fn default_protected_key_file(data_dir: &Path) -> PathBuf {
    data_dir.join(KEY_FILE_NAME)
}

#[derive(Debug)]
#[cfg_attr(not(feature = "sqlcipher"), allow(dead_code))]
struct LoadedDatabaseKey {
    key: String,
    provider: &'static str,
    created: bool,
}

#[cfg_attr(not(feature = "sqlcipher"), allow(dead_code))]
#[cfg(windows)]
fn load_or_create_platform_key(
    path: &Path,
) -> Result<LoadedDatabaseKey, DesktopDatabaseEncryptionError> {
    ProtectedDatabaseKeyFile::new(path.to_path_buf(), WindowsCurrentUserDpapi)
        .load_or_create_key_with(generate_sqlcipher_key)
}

#[cfg(not(windows))]
fn load_or_create_platform_key(
    _path: &Path,
) -> Result<LoadedDatabaseKey, DesktopDatabaseEncryptionError> {
    Err(DesktopDatabaseEncryptionError::ProviderUnavailable {
        platform: std::env::consts::OS,
    })
}

trait DatabaseKeyProtector {
    fn provider(&self) -> &'static str;

    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, DesktopDatabaseEncryptionError>;

    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, DesktopDatabaseEncryptionError>;
}

struct ProtectedDatabaseKeyFile<P> {
    path: PathBuf,
    protector: P,
}

impl<P> ProtectedDatabaseKeyFile<P>
where
    P: DatabaseKeyProtector,
{
    fn new(path: PathBuf, protector: P) -> Self {
        Self { path, protector }
    }

    fn load_or_create_key_with(
        &self,
        generate_key: impl FnOnce() -> Result<String, DesktopDatabaseEncryptionError>,
    ) -> Result<LoadedDatabaseKey, DesktopDatabaseEncryptionError> {
        if self.path.is_file() {
            return self.load_key(false);
        }

        let key = generate_key()?;
        validate_key(&key, &self.path)?;
        let protected = self.protector.protect(key.as_bytes())?;
        let envelope = ProtectedKeyEnvelope {
            format: KEY_FILE_FORMAT.to_owned(),
            provider: self.protector.provider().to_owned(),
            protected_key_hex: hex_encode(&protected),
        };
        if !write_key_envelope(&self.path, &envelope)? {
            return self.load_key(false);
        }
        Ok(LoadedDatabaseKey {
            key,
            provider: self.protector.provider(),
            created: true,
        })
    }

    fn load_key(&self, created: bool) -> Result<LoadedDatabaseKey, DesktopDatabaseEncryptionError> {
        let raw = std::fs::read_to_string(&self.path).map_err(|source| {
            DesktopDatabaseEncryptionError::Io {
                action: "read",
                path: self.path.clone(),
                source,
            }
        })?;
        let envelope: ProtectedKeyEnvelope =
            serde_json::from_str(&raw).map_err(|source| DesktopDatabaseEncryptionError::Json {
                path: self.path.clone(),
                source,
            })?;
        if envelope.format != KEY_FILE_FORMAT {
            return Err(DesktopDatabaseEncryptionError::InvalidEnvelope {
                path: self.path.clone(),
                reason: format!("unsupported format {}", envelope.format),
            });
        }
        if envelope.provider != self.protector.provider() {
            return Err(DesktopDatabaseEncryptionError::InvalidEnvelope {
                path: self.path.clone(),
                reason: format!(
                    "provider {} does not match this build's provider {}",
                    envelope.provider,
                    self.protector.provider()
                ),
            });
        }
        let protected = hex_decode(&envelope.protected_key_hex).map_err(|reason| {
            DesktopDatabaseEncryptionError::InvalidEnvelope {
                path: self.path.clone(),
                reason,
            }
        })?;
        let plaintext = self.protector.unprotect(&protected)?;
        let key = String::from_utf8(plaintext).map_err(|source| {
            DesktopDatabaseEncryptionError::InvalidEnvelope {
                path: self.path.clone(),
                reason: format!("decrypted SQLCipher key is not UTF-8: {source}"),
            }
        })?;
        validate_key(&key, &self.path)?;
        Ok(LoadedDatabaseKey {
            key,
            provider: self.protector.provider(),
            created,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct ProtectedKeyEnvelope {
    format: String,
    provider: String,
    protected_key_hex: String,
}

fn write_key_envelope(
    path: &Path,
    envelope: &ProtectedKeyEnvelope,
) -> Result<bool, DesktopDatabaseEncryptionError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| DesktopDatabaseEncryptionError::Io {
            action: "create directory for",
            path: path.to_path_buf(),
            source,
        })?;
    }

    let bytes = serde_json::to_vec_pretty(envelope).map_err(|source| {
        DesktopDatabaseEncryptionError::Json {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let tmp_path = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(KEY_FILE_NAME),
        std::process::id()
    ));
    let mut tmp = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)
        .map_err(|source| DesktopDatabaseEncryptionError::Io {
            action: "create temporary protected database-key file",
            path: tmp_path.clone(),
            source,
        })?;
    if let Err(source) = tmp.write_all(&bytes) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(DesktopDatabaseEncryptionError::Io {
            action: "write temporary protected database-key file",
            path: tmp_path,
            source,
        });
    }
    if let Err(source) = tmp.sync_all() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(DesktopDatabaseEncryptionError::Io {
            action: "flush temporary protected database-key file",
            path: tmp_path,
            source,
        });
    }
    drop(tmp);
    if path.exists() {
        let _ = std::fs::remove_file(&tmp_path);
        return Ok(false);
    }
    std::fs::rename(&tmp_path, path).map_err(|source| {
        let _ = std::fs::remove_file(&tmp_path);
        DesktopDatabaseEncryptionError::Io {
            action: "install protected database-key file",
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(true)
}

fn generate_sqlcipher_key() -> Result<String, DesktopDatabaseEncryptionError> {
    let mut key = [0_u8; GENERATED_KEY_BYTES];
    getrandom::fill(&mut key).map_err(DesktopDatabaseEncryptionError::Random)?;
    Ok(hex_encode(&key))
}

fn validate_key(key: &str, path: &Path) -> Result<(), DesktopDatabaseEncryptionError> {
    if key.trim().is_empty() {
        return Err(DesktopDatabaseEncryptionError::InvalidEnvelope {
            path: path.to_path_buf(),
            reason: "decrypted SQLCipher key is empty".to_owned(),
        });
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(raw: &str) -> Result<Vec<u8>, String> {
    if raw.len() % 2 != 0 {
        return Err("protected_key_hex has odd length".to_owned());
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for chunk in raw.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(chunk[0])
            .ok_or_else(|| "protected_key_hex contains non-hex data".to_owned())?;
        let lo = hex_nibble(chunk[1])
            .ok_or_else(|| "protected_key_hex contains non-hex data".to_owned())?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(windows)]
struct WindowsCurrentUserDpapi;

#[cfg(windows)]
impl DatabaseKeyProtector for WindowsCurrentUserDpapi {
    fn provider(&self) -> &'static str {
        WINDOWS_DPAPI_PROVIDER
    }

    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, DesktopDatabaseEncryptionError> {
        dpapi_protect(plaintext)
    }

    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, DesktopDatabaseEncryptionError> {
        dpapi_unprotect(protected)
    }
}

#[cfg(windows)]
fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>, DesktopDatabaseEncryptionError> {
    use std::ptr::null;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len().try_into().map_err(|_| {
            DesktopDatabaseEncryptionError::Provider {
                provider: WINDOWS_DPAPI_PROVIDER,
                operation: "protect",
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "SQLCipher key is too large for DPAPI",
                ),
            }
        })?,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let description: Vec<u16> = "Chancela SQLCipher database key"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut output = CRYPT_INTEGER_BLOB::default();

    let ok = unsafe {
        CryptProtectData(
            &mut input,
            description.as_ptr(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(DesktopDatabaseEncryptionError::Provider {
            provider: WINDOWS_DPAPI_PROVIDER,
            operation: "protect",
            source: std::io::Error::last_os_error(),
        });
    }

    let protected =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(protected)
}

#[cfg(windows)]
fn dpapi_unprotect(protected: &[u8]) -> Result<Vec<u8>, DesktopDatabaseEncryptionError> {
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: protected.len().try_into().map_err(|_| {
            DesktopDatabaseEncryptionError::Provider {
                provider: WINDOWS_DPAPI_PROVIDER,
                operation: "unprotect",
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "protected SQLCipher key is too large for DPAPI",
                ),
            }
        })?,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            null_mut(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(DesktopDatabaseEncryptionError::Provider {
            provider: WINDOWS_DPAPI_PROVIDER,
            operation: "unprotect",
            source: std::io::Error::last_os_error(),
        });
    }

    let plaintext =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(plaintext)
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
        fn new(name: &str) -> Self {
            let seq = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "chancela-desktop-db-encryption-{name}-{}-{seq}-{nanos}",
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

    #[derive(Clone, Copy)]
    struct TestProtector;

    impl DatabaseKeyProtector for TestProtector {
        fn provider(&self) -> &'static str {
            "test-protector"
        }

        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, DesktopDatabaseEncryptionError> {
            let mut protected = b"protected:".to_vec();
            protected.extend(plaintext.iter().rev());
            Ok(protected)
        }

        fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, DesktopDatabaseEncryptionError> {
            let Some(body) = protected.strip_prefix(b"protected:") else {
                return Err(DesktopDatabaseEncryptionError::Provider {
                    provider: self.provider(),
                    operation: "unprotect",
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "test protector prefix missing",
                    ),
                });
            };
            Ok(body.iter().rev().copied().collect())
        }
    }

    #[test]
    fn protected_key_file_creates_and_reuses_random_key_without_plaintext_storage() {
        let tmp = TempDir::new("create-reuse");
        let path = tmp.path().join("db-key.json");
        let key_file = ProtectedDatabaseKeyFile::new(path.clone(), TestProtector);

        let created = key_file
            .load_or_create_key_with(|| Ok("first-generated-key".to_owned()))
            .expect("create protected key");
        assert_eq!(created.key, "first-generated-key");
        assert_eq!(created.provider, "test-protector");
        assert!(created.created);

        let raw = std::fs::read_to_string(&path).expect("read protected key file");
        assert!(!raw.contains("first-generated-key"));
        assert!(raw.contains("test-protector"));

        let loaded = key_file
            .load_or_create_key_with(|| panic!("existing key file should be reused"))
            .expect("load protected key");
        assert_eq!(loaded.key, "first-generated-key");
        assert_eq!(loaded.provider, "test-protector");
        assert!(!loaded.created);
    }

    #[test]
    fn protected_key_file_rejects_mismatched_provider() {
        let tmp = TempDir::new("wrong-provider");
        let path = tmp.path().join("db-key.json");
        let envelope = ProtectedKeyEnvelope {
            format: KEY_FILE_FORMAT.to_owned(),
            provider: "other-provider".to_owned(),
            protected_key_hex: hex_encode(b"ciphertext"),
        };
        std::fs::write(&path, serde_json::to_vec_pretty(&envelope).expect("json"))
            .expect("write test envelope");

        let err = ProtectedDatabaseKeyFile::new(path, TestProtector)
            .load_or_create_key_with(|| Ok("unused".to_owned()))
            .expect_err("mismatched provider must be rejected");

        let message = err.to_string();
        assert!(message.contains("other-provider"));
        assert!(message.contains("test-protector"));
    }

    #[test]
    fn generated_sqlcipher_key_is_256_bit_hex_text() {
        let key = generate_sqlcipher_key().expect("generate key");
        assert_eq!(key.len(), GENERATED_KEY_BYTES * 2);
        assert!(key.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn plaintext_fallback_env_parser_requires_truthy_value() {
        for value in ["", "0", "false", "off", "no", " FALSE "] {
            assert!(!truthy_env_value(value), "{value:?} should be falsey");
        }
        for value in ["1", "true", "yes", "dev", " explicit "] {
            assert!(truthy_env_value(value), "{value:?} should be truthy");
        }
    }

    #[cfg(not(feature = "sqlcipher"))]
    #[test]
    fn no_sqlcipher_default_requires_explicit_plaintext_fallback() {
        let tmp = TempDir::new("no-sqlcipher");
        let err = resolve_database_encryption_config_with_plaintext_permission(tmp.path(), false)
            .expect_err("no-sqlcipher default must fail closed");
        assert!(matches!(
            err,
            DesktopDatabaseEncryptionError::SqlcipherUnavailable
        ));

        let resolved =
            resolve_database_encryption_config_with_plaintext_permission(tmp.path(), true)
                .expect("explicit plaintext fallback");
        assert_eq!(
            resolved.mode,
            ResolvedDatabaseEncryptionMode::ExplicitPlaintextFallback
        );
        assert!(!resolved.config.is_configured());
    }

    #[cfg(windows)]
    #[test]
    fn windows_dpapi_current_user_round_trips_protected_key() {
        let protector = WindowsCurrentUserDpapi;
        let plaintext = b"dpapi-test-sqlcipher-key";

        let protected = protector.protect(plaintext).expect("dpapi protect");
        assert_ne!(protected, plaintext);
        let round_trip = protector.unprotect(&protected).expect("dpapi unprotect");

        assert_eq!(round_trip, plaintext);
    }
}
