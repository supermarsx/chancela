//! Shared helpers: the run context, data-dir resolution, the confirmation gate, and the `users.json`
//! read/write that mirrors the api's on-disk contract (using the committed `chancela_api::User`).

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use chancela_api::{DatabaseEncryptionConfig, User};
use chancela_store::Store;
use time::OffsetDateTime;

/// The uniform command result: `Ok(true)` ⇒ success (exit 0), `Ok(false)` ⇒ a handled failure /
/// abort whose message was already printed (exit non-zero), `Err(_)` ⇒ an unexpected error `main`
/// prints. Using `Box<dyn Error>` lets every underlying `?` (store / io / serde / uuid) compose.
pub type Cmd = Result<bool, Box<dyn std::error::Error>>;

/// Environment variable naming the data directory (mirrors `chancela_api::DATA_DIR_ENV`).
pub const DATA_DIR_ENV: &str = "CHANCELA_DATA_DIR";
/// The `users.json` sidecar file name (the on-disk contract shared with the server).
pub const USERS_FILE: &str = "users.json";

/// The standard sidecar files/dirs bundled into a whole-instance archive and removed by a factory
/// reset — the same set the api's `POST /v1/backup` uses (a missing entry is tolerated by the store).
pub const SIDECAR_NAMES: &[&str] = &[
    "settings.json",
    "users.json",
    "roles.json",
    "delegations.json",
    "cae-catalog.json",
    "laws",
];

/// The resolved run context shared by every command.
pub struct Ctx {
    /// The data directory the command operates on (already resolved).
    pub data_dir: PathBuf,
    /// The actor recorded in audit events.
    pub actor: String,
    /// Whether to emit JSON for read commands.
    pub json: bool,
}

impl Ctx {
    /// Open (creating if absent) the durable store at the resolved data dir. Opening runs the
    /// idempotent forward schema migration and honors the same optional database encryption key env
    /// vars as server startup.
    pub fn open_store(&self) -> Result<Store, Box<dyn std::error::Error>> {
        let database_encryption = DatabaseEncryptionConfig::from_env()?;
        Ok(Store::open_with_options(
            &self.data_dir,
            database_encryption.store_open_options(),
        )?)
    }

    /// The standard sidecar paths under this data dir (for backup / reset / start-over).
    pub fn sidecars(&self) -> Vec<PathBuf> {
        SIDECAR_NAMES
            .iter()
            .map(|n| self.data_dir.join(n))
            .collect()
    }

    /// The `users.json` path under this data dir.
    pub fn users_path(&self) -> PathBuf {
        self.data_dir.join(USERS_FILE)
    }
}

/// Resolve the data dir the way `chancela_api::AppState::resolve_data_dir` does, but always yield a
/// concrete path (a host tool operates on disk): `--data-dir` › `$CHANCELA_DATA_DIR` › an existing
/// `chancela-data/` (walking up) › `./chancela-data`.
pub fn resolve_data_dir(flag: Option<PathBuf>) -> PathBuf {
    if let Some(dir) = flag {
        return dir;
    }
    if let Ok(raw) = std::env::var(DATA_DIR_ENV)
        && !raw.trim().is_empty()
    {
        return PathBuf::from(raw);
    }
    if let Ok(start) = std::env::current_dir() {
        for base in start.ancestors() {
            let candidate = base.join("chancela-data");
            if candidate.is_dir() {
                return candidate;
            }
        }
    }
    PathBuf::from("chancela-data")
}

/// The current instant used as the caller-supplied `at` for recovery/audit events.
pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// Lowercase-hex encode a byte slice (chain head / digest display).
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The destructive-operation gate. Returns `true` when the operation may proceed.
///
/// `--yes` proceeds immediately. Otherwise, if stdin is an interactive terminal, the operator must
/// type `expect` exactly; a non-terminal stdin (scripts, CI, tests) is **refused** so a destructive
/// op is never run non-interactively without an explicit `--yes`.
pub fn confirm(expect: &str, yes: bool) -> Result<bool, std::io::Error> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "Refusing: destructive operation and --yes was not given (stdin is not a terminal)."
        );
        return Ok(false);
    }
    eprint!("Type '{expect}' to confirm: ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim() == expect)
}

/// Validate a username the same way the api does (lowercase slug, non-empty, ≤64) so the CLI never
/// writes a profile the server would reject.
pub fn validate_username(raw: &str) -> Result<String, String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err("username must not be empty".to_owned());
    }
    if name.len() > 64 {
        return Err("username must be at most 64 characters".to_owned());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err("username must be a lowercase slug of a-z, 0-9, '.', '_' or '-'".to_owned());
    }
    Ok(name.to_owned())
}

/// Read the `users.json` array (an absent file ⇒ empty). A malformed file is a hard error here (the
/// CLI must not silently drop existing profiles when about to write them back).
pub fn read_users(path: &Path) -> Result<Vec<User>, Box<dyn std::error::Error>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice::<Vec<User>>(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(Box::new(e)),
    }
}

/// Atomically write the `users.json` array (tmp file + rename), sorted by `created_at` then id — the
/// same deterministic document shape the api writes.
pub fn write_users_atomic(path: &Path, users: &[User]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut list: Vec<&User> = users.iter().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
    let tmp = path.with_extension(format!("json.{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Locate the sibling `chancela-server` binary (installed alongside `chancela`), falling back to the
/// bare name on `PATH`.
pub fn server_binary() -> PathBuf {
    let name = if cfg!(windows) {
        "chancela-server.exe"
    } else {
        "chancela-server"
    };
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join(name);
        if sibling.exists() {
            return sibling;
        }
    }
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_prefers_flag() {
        let p = resolve_data_dir(Some(PathBuf::from("/tmp/explicit")));
        assert_eq!(p, PathBuf::from("/tmp/explicit"));
    }

    #[test]
    fn validate_username_rules() {
        assert_eq!(
            validate_username("  amelia.marques "),
            Ok("amelia.marques".to_owned())
        );
        assert!(validate_username("").is_err());
        assert!(validate_username("Has Space").is_err());
        assert!(validate_username("UPPER").is_err());
    }
}
