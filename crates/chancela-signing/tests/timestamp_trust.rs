use std::path::{Path, PathBuf};
use std::process::Command;

use chancela_signing::{
    TimestampTrustDecision, TimestampTrustPolicy, TrustedListStatus, validate_timestamp_trust,
};
use chancela_tsl::{QtstMatchDetails, QtstServiceMatch, QualifiedStatus, ServiceStatus};
use time::OffsetDateTime;

const POLICY_OID: &str = "1.2.3.4.1";

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "chancela-signing-tsa-trust-{}-{}",
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

fn test_chain() -> Option<(Vec<u8>, Vec<u8>)> {
    if !openssl_available() {
        eprintln!("skipping OpenSSL-backed timestamp trust test: openssl not found");
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
    std::fs::write(
        dir.join("leaf.ext"),
        "basicConstraints = critical,CA:FALSE\n\
         keyUsage = critical,digitalSignature\n\
         extendedKeyUsage = critical,timeStamping\n",
    )
    .expect("write leaf extensions");
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

fn timestamp(leaf: Vec<u8>) -> chancela_tsa::Timestamp {
    chancela_tsa::Timestamp {
        token_der: vec![0x30, 0x00],
        gen_time: OffsetDateTime::now_utc(),
        serial_number: vec![0x01],
        policy: POLICY_OID.to_owned(),
        tsa_certificate_der: Some(leaf),
        embedded_certificate_ders: Vec::new(),
    }
}

fn qtst_details(root: Vec<u8>, authenticated: bool) -> QtstMatchDetails {
    QtstMatchDetails {
        status: QualifiedStatus::Granted,
        matches: vec![QtstServiceMatch {
            provider_name: "Chancela Test QTSP".to_owned(),
            service_name: "Chancela Test QTST".to_owned(),
            service_status: ServiceStatus::Granted,
            granted_and_effective: true,
            trust_anchor_ders: vec![root.clone()],
        }],
        trust_anchor_ders: vec![root],
        authenticated,
    }
}

#[test]
fn timestamp_trust_accepts_authenticated_qtst_anchor_policy_and_path() {
    let Some((leaf, root)) = test_chain() else {
        return;
    };
    let ts = timestamp(leaf);
    let qtst = qtst_details(root, true);

    let report = validate_timestamp_trust(
        &ts,
        &qtst,
        &TimestampTrustPolicy::require_one_of([POLICY_OID]),
    );

    assert_eq!(report.decision, TimestampTrustDecision::Accepted);
    assert_eq!(report.policy_oid_accepted, Some(true));
    assert_eq!(report.trusted_list_status, TrustedListStatus::Granted);
    assert!(report.trusted_list_authenticated);
    assert!(report.certificate_path_valid);
    assert_eq!(report.certificate_path_anchor_index, Some(0));
    assert_eq!(report.certificate_path_len, Some(2));
    assert_eq!(report.qtst_matches.len(), 1);
    assert!(report.scope_note.contains("no legal qualification claim"));
}

#[test]
fn timestamp_trust_rejects_unconfigured_policy_oid() {
    let Some((leaf, root)) = test_chain() else {
        return;
    };
    let ts = timestamp(leaf);
    let qtst = qtst_details(root, true);

    let report = validate_timestamp_trust(
        &ts,
        &qtst,
        &TimestampTrustPolicy::require_one_of(["1.3.6.1.4.1.99999.1"]),
    );

    assert_eq!(report.decision, TimestampTrustDecision::Rejected);
    assert_eq!(report.policy_oid_accepted, Some(false));
    assert!(report.certificate_path_valid);
    assert!(
        report
            .failure_reasons
            .iter()
            .any(|reason| reason.contains("policy OID"))
    );
}

#[test]
fn timestamp_trust_downgrades_unauthenticated_tsl_grants() {
    let ts = timestamp(b"not-a-real-cert".to_vec());
    let qtst = qtst_details(b"not-a-real-anchor".to_vec(), false);

    let report = validate_timestamp_trust(&ts, &qtst, &TimestampTrustPolicy::default());

    assert_eq!(report.decision, TimestampTrustDecision::Rejected);
    assert_eq!(report.trusted_list_status, TrustedListStatus::Unknown);
    assert!(!report.trusted_list_authenticated);
    assert!(!report.certificate_path_valid);
    assert!(
        report
            .failure_reasons
            .iter()
            .any(|reason| reason.contains("downgraded to Unknown"))
    );
}
