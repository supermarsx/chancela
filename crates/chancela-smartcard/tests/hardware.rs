//! Real-hardware tests: a card reader + Autenticação.gov middleware + a Cartão
//! de Cidadão must be present. Double-gated — the whole file is behind the
//! `hardware-tests` feature AND every test is `#[ignore]`, so it never runs in
//! CI and even locally needs `--features hardware-tests -- --ignored`
//! (plan §2.4). See `TESTING.md` for setup.
#![cfg(feature = "hardware-tests")]

use chancela_smartcard::{CryptoToken, Pkcs11Token, detect, select_signature_certificate};

#[test]
#[ignore = "requires a connected PC/SC reader"]
fn enumerate_real_readers() {
    let readers = detect().expect("PC/SC service must be running");
    println!("detected {} reader(s):", readers.len());
    for r in &readers {
        println!("  - {}", r.name);
    }
}

#[test]
#[ignore = "requires the Autenticação.gov middleware + an inserted card"]
fn list_real_certificates() {
    let token = Pkcs11Token::open().expect("middleware module + inserted card");
    let certs = token.list_certificates().expect("enumerate certificates");
    assert!(
        select_signature_certificate(&certs).is_some(),
        "the card should expose a CITIZEN SIGNATURE CERTIFICATE"
    );
    for c in &certs {
        println!("cert: {:<40} algo={:?}", c.label, c.algorithm);
    }
}

#[test]
#[ignore = "prompts for the citizen's signature PIN via the middleware"]
fn sign_with_real_card() {
    let token = Pkcs11Token::open().expect("middleware module + inserted card");
    let certs = token.list_certificates().expect("enumerate certificates");
    let cert = select_signature_certificate(&certs).expect("signature certificate");

    // SHA-256 of an arbitrary payload.
    let digest = [0x11u8; 32];
    let sig = token
        .sign_digest(cert, &digest)
        .expect("NULL-PIN protected-auth-path signing");
    assert!(!sig.signature.is_empty());
    println!(
        "produced {}-byte {:?} signature",
        sig.signature.len(),
        sig.algorithm
    );
}
