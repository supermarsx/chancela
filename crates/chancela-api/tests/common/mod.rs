pub mod tsa_http;

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHasher, SaltString};
use std::sync::Once;

pub const TEST_PASSWORD: &str = "Teste-Forte7!X";

/// Install one deterministic operator credential key for integration-test binaries that exercise
/// durable encrypted credentials on hosts without an OS credential-sealing provider.
///
/// Keep the key configured for the process lifetime so parallel tests cannot observe a transient
/// environment. Callers opt in explicitly from suites whose contract requires credential writes.
#[allow(dead_code)]
pub fn ensure_credential_key() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        std::env::set_var(
            "CHANCELA_CREDENTIAL_KEY",
            "chancela-integration-test-credential-key-0001",
        );
        std::env::remove_var("CHANCELA_CREDENTIAL_KEY_FILE");
        std::env::remove_var("CHANCELA_CREDENTIAL_STRICT");
    });
}

#[allow(dead_code)]
pub fn password_hash() -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(TEST_PASSWORD.as_bytes(), &salt)
        .expect("test password hashes")
        .to_string()
}
