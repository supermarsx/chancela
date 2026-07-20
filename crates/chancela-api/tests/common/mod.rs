pub mod tsa_http;

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHasher, SaltString};

pub const TEST_PASSWORD: &str = "Teste-Forte7!X";

#[allow(dead_code)]
pub fn password_hash() -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(TEST_PASSWORD.as_bytes(), &salt)
        .expect("test password hashes")
        .to_string()
}
