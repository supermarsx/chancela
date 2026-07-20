use std::path::{Path, PathBuf};
use std::process::Command;

use chancela_tsa::{TsaError, validate_tsa_certificate_path};
use time::OffsetDateTime;

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "chancela-tsa-path-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create temp cert dir");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .status()
        .is_ok_and(|status| status.success())
}

fn run(dir: &Path, args: &[&str]) {
    let status = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .status()
        .expect("run openssl");
    assert!(status.success(), "openssl {:?} failed", args);
}

fn write_ext(path: &Path, eku: Option<&str>, key_usage: &str) {
    let eku_line = eku
        .map(|value| format!("extendedKeyUsage = critical,{value}\n"))
        .unwrap_or_default();
    std::fs::write(
        path,
        format!(
            "basicConstraints = critical,CA:FALSE\nkeyUsage = critical,{key_usage}\n{eku_line}"
        ),
    )
    .expect("write extension file");
}

fn test_chain(eku: Option<&str>, key_usage: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    if !openssl_available() {
        eprintln!("skipping OpenSSL-backed certificate path test: openssl not found");
        return None;
    }

    let dir = TestDir::new();
    run(&dir.path, &["genrsa", "-out", "root.key", "2048"]);
    run(
        &dir.path,
        &[
            "req",
            "-x509",
            "-new",
            "-key",
            "root.key",
            "-sha256",
            "-days",
            "3650",
            "-subj",
            "/CN=Chancela Test TSA Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-out",
            "root.pem",
        ],
    );
    run(&dir.path, &["genrsa", "-out", "leaf.key", "2048"]);
    run(
        &dir.path,
        &[
            "req",
            "-new",
            "-key",
            "leaf.key",
            "-subj",
            "/CN=Chancela Test TSA Signer",
            "-out",
            "leaf.csr",
        ],
    );
    write_ext(&dir.join("leaf.ext"), eku, key_usage);
    run(
        &dir.path,
        &[
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "root.pem",
            "-CAkey",
            "root.key",
            "-set_serial",
            "2",
            "-sha256",
            "-days",
            "365",
            "-extfile",
            "leaf.ext",
            "-out",
            "leaf.pem",
        ],
    );
    run(
        &dir.path,
        &[
            "x509", "-in", "root.pem", "-outform", "DER", "-out", "root.der",
        ],
    );
    run(
        &dir.path,
        &[
            "x509", "-in", "leaf.pem", "-outform", "DER", "-out", "leaf.der",
        ],
    );

    Some((
        std::fs::read(dir.join("leaf.der")).expect("read leaf der"),
        std::fs::read(dir.join("root.der")).expect("read root der"),
    ))
}

#[test]
fn validates_tsa_leaf_to_supplied_anchor() {
    let Some((leaf, root)) = test_chain(Some("timeStamping"), "digitalSignature") else {
        return;
    };

    let result =
        validate_tsa_certificate_path(&leaf, &[], &[root], OffsetDateTime::now_utc()).unwrap();
    assert_eq!(result.path_der.len(), 2);
    assert_eq!(result.trust_anchor_index, 0);
}

#[test]
fn rejects_leaf_without_timestamping_eku() {
    let Some((leaf, root)) = test_chain(None, "digitalSignature") else {
        return;
    };

    let err =
        validate_tsa_certificate_path(&leaf, &[], &[root], OffsetDateTime::now_utc()).unwrap_err();
    assert!(
        matches!(err, TsaError::CertificatePath(message) if message.contains("extendedKeyUsage"))
    );
}

#[test]
fn rejects_leaf_key_usage_without_digital_signature() {
    let Some((leaf, root)) = test_chain(Some("timeStamping"), "keyEncipherment") else {
        return;
    };

    let err =
        validate_tsa_certificate_path(&leaf, &[], &[root], OffsetDateTime::now_utc()).unwrap_err();
    assert!(
        matches!(err, TsaError::CertificatePath(message) if message.contains("digitalSignature"))
    );
}
