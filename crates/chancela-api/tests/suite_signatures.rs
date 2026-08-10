#[path = "common/mod.rs"]
mod common;

#[path = "asic_signature_validation.rs"]
mod asic_signature_validation;
#[path = "attestation_key_at_create.rs"]
mod attestation_key_at_create;
#[path = "batch_signing.rs"]
mod batch_signing;
#[path = "cc_signing.rs"]
mod cc_signing;
#[path = "external_signer_invites.rs"]
mod external_signer_invites;
#[path = "external_signing_envelopes.rs"]
mod external_signing_envelopes;
#[path = "ltv.rs"]
mod ltv;
#[path = "official_signature_import.rs"]
mod official_signature_import;
#[path = "signing_configure_gate.rs"]
mod signing_configure_gate;
#[path = "trust_anchor_suggestions.rs"]
mod trust_anchor_suggestions;
#[path = "trust_read_path_anchors.rs"]
mod trust_read_path_anchors;
#[path = "xades_signature.rs"]
mod xades_signature;

#[cfg(test)]
mod tsa_http_tests {
    use std::collections::HashSet;
    use std::sync::{Arc, Barrier};

    use super::common::tsa_http::OpensslTsaDir;

    #[test]
    fn openssl_tsa_dirs_with_the_same_timestamp_are_unique_and_cleaned_on_drop() {
        const DIR_COUNT: usize = 32;
        const FIXED_TIMESTAMP_NANOS: i128 = 1_753_459_200_000_000_000;

        let start = Arc::new(Barrier::new(DIR_COUNT));
        let handles = (0..DIR_COUNT)
            .map(|_| {
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    let dir = OpensslTsaDir::new_at_timestamp_for_test(FIXED_TIMESTAMP_NANOS)
                        .expect("create mock TSA directory");
                    let path = dir.path_for_test().to_path_buf();
                    assert!(path.is_dir(), "mock TSA directory should exist");
                    (dir, path)
                })
            })
            .collect::<Vec<_>>();

        let dirs = handles
            .into_iter()
            .map(|handle| handle.join().expect("mock TSA directory worker"))
            .collect::<Vec<_>>();
        let paths = dirs
            .iter()
            .map(|(_, path)| path.clone())
            .collect::<HashSet<_>>();

        assert_eq!(paths.len(), DIR_COUNT);
        assert!(paths.iter().all(|path| path.is_dir()));

        drop(dirs);
        assert!(paths.iter().all(|path| !path.exists()));
    }
}
