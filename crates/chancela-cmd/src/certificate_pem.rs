//! Normalising a pasted X.509 certificate PEM, and refusing the rest by name.
//!
//! # Why this exists
//!
//! `ama_cert_pem` is filled by an operator pasting a block of text. Real paste is dirty: CRLF from
//! Windows, a UTF-8 BOM, trailing spaces on every line, a stray NUL from a terminal capture,
//! non-breaking spaces and zero-width characters from a word processor, no trailing newline, or the
//! whole certificate collapsed onto one line. The RFC 7468 reader behind
//! [`crate::FieldEncryptor::from_ama_cert_pem`] is strict, so most of that made a perfectly good
//! certificate unusable with a message that named none of it.
//!
//! # The distinction this module is built on
//!
//! **Whitespace does not survive into the decoded bytes.** RFC 7468 §3 defines the encapsulated
//! portion as base64 with line breaks; base64 itself has no meaning for any character outside its
//! 65-character alphabet. So removing whitespace — and, for the same reason, the invisible
//! formatting characters that carry no base64 value either — provably cannot change the DER. That
//! is a *normalisation*.
//!
//! **Anything that would change the decoded bytes is a corruption, and is refused.** A smart quote
//! where a slash should be, an en dash in the armour, a mangled `BEGIN` line, two certificates
//! where one was expected: each of those is a real difference between what the operator has and
//! what they meant to have. Guessing a repair would produce a certificate nobody chose, and the
//! failure would only surface later as a production signature that encrypts a citizen's PIN to the
//! wrong key. Every one of them returns a [`CertificatePemError`] variant that names it.
//!
//! # What "canonical" means here
//!
//! [`normalize_certificate_pem`] does not hand back the operator's text with the whitespace tidied.
//! It decodes to DER, checks that the DER really is an X.509 certificate, and then **re-emits the
//! PEM from those verified bytes**: one `BEGIN` line, base64 wrapped at 64 columns, one `END` line,
//! one trailing newline. That is not a repair — the output is a function of the decoded bytes and
//! nothing else, so it cannot differ from the input in anything but layout, and
//! [`NormalizedCertificate::der`] is the proof. It is what makes the one-line paste work without a
//! single guess, and it means there is exactly one stored representation of any given certificate.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Decode;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_cert::Certificate;

use crate::error::CmdError;

/// The one PEM label this module accepts.
const CERTIFICATE_LABEL: &str = "CERTIFICATE";
/// The opening encapsulation boundary, in full.
const BEGIN_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";
/// The closing encapsulation boundary, in full.
const END_CERTIFICATE: &str = "-----END CERTIFICATE-----";
/// The prefix every RFC 7468 opening boundary shares, used to find blocks of *any* label.
const BEGIN_PREFIX: &str = "-----BEGIN ";
/// The boundary terminator, used to read a block's label back out.
const BOUNDARY_DASHES: &str = "-----";
/// Column width the canonical output wraps base64 at (RFC 7468 §2).
const PEM_LINE_WIDTH: usize = 64;

/// Why a candidate certificate could not be turned into usable DER.
///
/// Each variant names one specific thing that was wrong, because "invalid certificate" tells an
/// operator holding a 2 KiB block of base64 nothing they can act on. The API layer maps these onto
/// stable diagnostic codes so the sentence an operator reads is in their own language.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CertificatePemError {
    /// Nothing but whitespace and invisible characters was supplied.
    #[error("no certificate was supplied")]
    Empty,

    /// No `-----BEGIN <label>-----` boundary at all. Typically a truncated copy, or armour whose
    /// dashes a word processor replaced with a dash character that is not `-`.
    #[error(
        "no PEM armour was found: the text must contain a line reading exactly \
         \"{BEGIN_CERTIFICATE}\""
    )]
    ArmourMissing,

    /// An opening boundary was found but the matching `-----END CERTIFICATE-----` was not.
    #[error("the \"{BEGIN_CERTIFICATE}\" line has no matching \"{END_CERTIFICATE}\" line")]
    EndArmourMissing,

    /// The block is PEM, but not a certificate — most importantly, a private key. Never repaired
    /// into one: the two are different objects and only one of them belongs in this field.
    #[error(
        "the text is a PEM block labelled \"{label}\", not \"{CERTIFICATE_LABEL}\"; \
         this field takes AMA's public certificate"
    )]
    WrongLabel {
        /// The label read from between the boundary dashes, verbatim.
        label: String,
    },

    /// More than one PEM block — a chain, or a certificate with its key pasted after it. Refused
    /// rather than resolved: choosing one of them would be choosing for the operator.
    #[error(
        "the text contains {count} PEM blocks; paste exactly one certificate, \
         not a chain or a bundle"
    )]
    MultipleBlocks {
        /// How many opening boundaries were counted.
        count: usize,
    },

    /// A character inside the base64 body that is neither base64 nor ignorable whitespace. This is
    /// the smart-quote and mangled-character case, and it is where the "normalise, never repair"
    /// line is actually drawn: dropping it or guessing at what it replaced would change the key
    /// this certificate is trusted to carry.
    #[error(
        "the certificate body contains {character} at byte offset {offset}, which is neither \
         base64 nor whitespace; it was left in place rather than guessed at"
    )]
    IllegalCharacter {
        /// The offending character in `U+XXXX` notation — never the raw character, which may be
        /// invisible, a control code, or a bidirectional override.
        character: String,
        /// Byte offset in the text as supplied.
        offset: usize,
    },

    /// Every character was in the base64 alphabet and the body still did not decode: a truncated
    /// paste, or padding that does not match the length. Not re-padded — the missing bytes are not
    /// recoverable and inventing them would fabricate key material.
    #[error("the certificate body is not valid base64: {detail}")]
    Base64Invalid {
        /// The decoder's own message.
        detail: String,
    },

    /// The bytes decoded, and are not an X.509 certificate.
    #[error("the decoded bytes are not an X.509 certificate: {detail}")]
    NotACertificate {
        /// The DER reader's own message.
        detail: String,
    },
}

impl From<CertificatePemError> for CmdError {
    fn from(err: CertificatePemError) -> Self {
        CmdError::Encryption(err.to_string())
    }
}

/// A certificate that parsed, together with the bytes that prove what it is.
///
/// [`der`](Self::der) is the whole point: it is the decoded certificate, and every other member is
/// derived from it. Two inputs that normalise to the same `der` are the same certificate however
/// differently they were pasted, and [`sha256_fingerprint`](Self::sha256_fingerprint) is how an
/// operator checks that against what AMA issued them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedCertificate {
    pem: String,
    der: Vec<u8>,
    removed_characters: usize,
}

impl NormalizedCertificate {
    /// The canonical PEM: `BEGIN`, base64 of [`der`](Self::der) wrapped at 64 columns, `END`, one
    /// trailing newline. This is the form that should be stored, so the value later handed to a
    /// strict reader is already one a strict reader accepts.
    pub fn pem(&self) -> &str {
        &self.pem
    }

    /// The decoded certificate bytes.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// How many *unexpected* ignorable characters the body carried.
    ///
    /// Line breaks are excluded: wrapping the base64 across lines is what PEM looks like, and
    /// counting it would make every ordinary certificate look as though it had been cleaned up.
    /// What this counts is the rest — trailing spaces, tabs, a no-break space, a stray NUL, a
    /// zero-width character. Reported rather than swallowed: an operator is entitled to know the
    /// text they pasted was not the text that was read, even when the difference provably could not
    /// change the decoded bytes.
    pub fn removed_characters(&self) -> usize {
        self.removed_characters
    }

    /// SHA-256 of the DER, as 64 lowercase hex characters — the same shape the trust-anchor
    /// fingerprints in the signing settings use, so the two are comparable by eye.
    ///
    /// This is deliberately over the DER and not over the PEM text: a fingerprint that moved when
    /// somebody re-wrapped the base64 would be useless for the one job it has, which is letting an
    /// operator confirm that this is the certificate AMA issued them.
    pub fn sha256_fingerprint(&self) -> String {
        let digest = Sha256::digest(&self.der);
        let mut out = String::with_capacity(64);
        for byte in digest {
            out.push(char::from_digit((byte >> 4) as u32, 16).expect("high nibble < 16"));
            out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("low nibble < 16"));
        }
        out
    }
}

/// Whether a character carries no base64 information and may therefore be dropped from the body.
///
/// Three groups, and the reason is the same for all three — none of them is in the base64 alphabet,
/// so none of them can contribute a bit to the decoded output:
///
/// - **Unicode whitespace** (`char::is_whitespace`, i.e. the `White_Space` property). Covers space,
///   tab, LF, CR, form feed, the no-break space a word processor substitutes, and the exotic spaces.
///   RFC 7468 already says line breaks in the body are not data.
/// - **Control characters** (Unicode `Cc`: U+0000–U+001F, U+007F–U+009F). The stray NUL out of a
///   terminal capture, and its neighbours.
/// - **Zero-width formatting** (U+200B–U+200D, U+2060, U+FEFF). Invisible, and inserted by editors
///   and web pages rather than by anything that produced the certificate.
///
/// Everything else is refused. Note what is NOT here: a curly quote, an en dash, a Cyrillic letter
/// that looks like a Latin one. Those are outside the alphabet too, but they sit where a real base64
/// character was, so removing them would silently shorten the body and decode to different bytes.
fn is_ignorable_in_body(c: char) -> bool {
    c.is_whitespace()
        || c.is_control()
        || matches!(c, '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}')
}

/// Normalise a pasted certificate, verify it, and return the canonical form — or say what is wrong.
///
/// The order is fixed and is the contract: **normalise the safe classes, then verify, then refuse.**
/// Nothing is repaired between the second and third steps.
///
/// # Errors
///
/// Every [`CertificatePemError`] variant, each naming one specific defect. A certificate that is
/// merely *expired* is not an error here — that is a determinable fact about a perfectly well-formed
/// certificate, and it is the caller's to report.
pub fn normalize_certificate_pem(
    input: &str,
) -> Result<NormalizedCertificate, CertificatePemError> {
    // A leading BOM is an encoding artefact of the file the text came out of, never content.
    let bom = if input.starts_with('\u{FEFF}') {
        '\u{FEFF}'.len_utf8()
    } else {
        0
    };
    let text = &input[bom..];

    if text.chars().all(is_ignorable_in_body) {
        return Err(CertificatePemError::Empty);
    }

    // Count blocks of ANY label first, so "you pasted a private key" and "you pasted a chain" are
    // told apart from "there is no armour here" instead of collapsing into one vague refusal.
    let labels = pem_block_labels(text);
    match labels.len() {
        0 => return Err(CertificatePemError::ArmourMissing),
        1 => {}
        count => return Err(CertificatePemError::MultipleBlocks { count }),
    }
    if labels[0] != CERTIFICATE_LABEL {
        return Err(CertificatePemError::WrongLabel {
            label: labels[0].clone(),
        });
    }

    // The label is CERTIFICATE, so the exact opening boundary is present by construction.
    let begin = text
        .find(BEGIN_CERTIFICATE)
        .ok_or(CertificatePemError::ArmourMissing)?;
    let body_start = begin + BEGIN_CERTIFICATE.len();
    let body_len = text[body_start..]
        .find(END_CERTIFICATE)
        .ok_or(CertificatePemError::EndArmourMissing)?;
    let body = &text[body_start..body_start + body_len];

    // Text before BEGIN and after END is explanatory matter (RFC 7468 §5.2) — `openssl x509 -text`
    // emits a whole certificate dump above the block. It is outside the encapsulation and is
    // dropped, which cannot affect the decode.
    let mut base64_body = String::with_capacity(body.len());
    let mut removed_characters = 0usize;
    for (offset, c) in body.char_indices() {
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=') {
            base64_body.push(c);
        } else if is_ignorable_in_body(c) {
            // `\n` and `\r` are the layout PEM is supposed to have; everything else was noise.
            if !matches!(c, '\n' | '\r') {
                removed_characters += 1;
            }
        } else {
            return Err(CertificatePemError::IllegalCharacter {
                character: format!("U+{:04X}", c as u32),
                offset: bom + body_start + offset,
            });
        }
    }

    let der = STANDARD
        .decode(&base64_body)
        .map_err(|e| CertificatePemError::Base64Invalid {
            detail: e.to_string(),
        })?;

    // Verify BEFORE re-emitting: the canonical PEM is only allowed to exist for bytes that really
    // are a certificate, so nothing downstream can be handed a tidy-looking block of nonsense.
    Certificate::from_der(&der).map_err(|e| CertificatePemError::NotACertificate {
        detail: e.to_string(),
    })?;

    Ok(NormalizedCertificate {
        pem: canonical_pem(&der),
        der,
        removed_characters,
    })
}

/// The labels of every `-----BEGIN <label>-----` boundary in `text`, in order.
fn pem_block_labels(text: &str) -> Vec<String> {
    let mut labels = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative) = text[cursor..].find(BEGIN_PREFIX) {
        let label_start = cursor + relative + BEGIN_PREFIX.len();
        match text[label_start..].find(BOUNDARY_DASHES) {
            Some(label_len) => {
                labels.push(text[label_start..label_start + label_len].to_owned());
                cursor = label_start + label_len;
            }
            // An opening prefix that never terminates is not a block; skip past it and keep looking
            // rather than counting it, so a stray `-----BEGIN ` in prose cannot become a "block".
            None => cursor = label_start,
        }
    }
    labels
}

/// Emit RFC 7468 PEM for `der`. A pure function of the bytes — that is what makes it canonical.
fn canonical_pem(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut out = String::with_capacity(body.len() + body.len() / PEM_LINE_WIDTH + 64);
    out.push_str(BEGIN_CERTIFICATE);
    out.push('\n');
    for chunk in body.as_bytes().chunks(PEM_LINE_WIDTH) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 output is ASCII"));
        out.push('\n');
    }
    out.push_str(END_CERTIFICATE);
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::DecodePem;
    use der::Encode;

    const CLEAN: &str = include_str!("../fixtures/ama_encryption_cert.pem");

    /// The DER a STRICT reader gets from the already-clean fixture, with no normalisation involved.
    ///
    /// This is the reference every other decode in this module is measured against: `der`'s own
    /// RFC 7468 decoder, reading the operator's file exactly as delivered.
    fn reference_der() -> Vec<u8> {
        let (label, der) =
            der::pem::decode_vec(CLEAN.as_bytes()).expect("the fixture is clean PEM");
        assert_eq!(label, CERTIFICATE_LABEL);
        der
    }

    /// The certificate body of the fixture, with every line break removed.
    fn body_of(pem: &str) -> String {
        let start = pem.find(BEGIN_CERTIFICATE).unwrap() + BEGIN_CERTIFICATE.len();
        let len = pem[start..].find(END_CERTIFICATE).unwrap();
        pem[start..start + len]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    }

    /// Every way the same certificate can arrive, and they must all be the same certificate.
    ///
    /// Named so a failure says which dirt class broke, rather than "case 4".
    fn filthy_variants() -> Vec<(&'static str, String)> {
        let body = body_of(CLEAN);
        let wrapped: Vec<&str> = body
            .as_bytes()
            .chunks(PEM_LINE_WIDTH)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();

        vec![
            ("crlf", CLEAN.replace('\n', "\r\n")),
            ("bare-cr", CLEAN.replace('\n', "\r")),
            ("utf8-bom", format!("\u{FEFF}{CLEAN}")),
            (
                "trailing-spaces-on-every-line",
                CLEAN
                    .lines()
                    .map(|line| format!("{line}   \n"))
                    .collect::<String>(),
            ),
            ("no-trailing-newline", CLEAN.trim_end().to_owned()),
            ("extra-trailing-newlines", format!("{CLEAN}\n\n\n")),
            (
                "one-line",
                format!("{BEGIN_CERTIFICATE}{body}{END_CERTIFICATE}"),
            ),
            (
                "embedded-nul-and-c0-controls",
                format!(
                    "{BEGIN_CERTIFICATE}\n{}\0{}\u{0007}\n{END_CERTIFICATE}\n",
                    wrapped[0],
                    wrapped[1..].join("\n"),
                ),
            ),
            (
                "non-breaking-and-zero-width-spaces",
                format!(
                    "{BEGIN_CERTIFICATE}\n{}\u{00A0}\u{200B}\n{}\u{FEFF}\n{END_CERTIFICATE}\n",
                    wrapped[0],
                    wrapped[1..].join("\n"),
                ),
            ),
            (
                "explanatory-text-around-the-block",
                format!(
                    "subject=CN = AMA\nissuer=CN = AMA\n{}\nNotes pasted after the block.\n",
                    CLEAN.trim_end(),
                ),
            ),
            (
                "everything-at-once",
                format!(
                    "\u{FEFF}subject=CN = AMA\r\n{BEGIN_CERTIFICATE}\r\n{}\u{00A0}\0\r\n{END_CERTIFICATE}",
                    body,
                ),
            ),
        ]
    }

    #[test]
    fn a_clean_certificate_normalises_to_exactly_what_a_strict_reader_decoded() {
        let normalized = normalize_certificate_pem(CLEAN).expect("the fixture must normalise");
        assert_eq!(
            normalized.der(),
            reference_der().as_slice(),
            "normalising an already-clean PEM moved the decoded bytes"
        );
        assert_eq!(normalized.removed_characters(), 0);
        // And the signing path's own reader agrees with both.
        let via_signing_path = Certificate::from_pem(CLEAN.as_bytes())
            .unwrap()
            .to_der()
            .unwrap();
        assert_eq!(normalized.der(), via_signing_path.as_slice());
    }

    #[test]
    fn every_filthy_variant_yields_byte_identical_der_and_one_fingerprint() {
        let reference = reference_der();
        let expected_fingerprint = normalize_certificate_pem(CLEAN)
            .unwrap()
            .sha256_fingerprint();
        assert_eq!(expected_fingerprint.len(), 64);

        for (name, candidate) in filthy_variants() {
            let normalized = normalize_certificate_pem(&candidate)
                .unwrap_or_else(|e| panic!("variant {name:?} must normalise, got {e}"));
            assert_eq!(
                normalized.der(),
                reference.as_slice(),
                "variant {name:?} decoded to different bytes"
            );
            assert_eq!(
                normalized.sha256_fingerprint(),
                expected_fingerprint,
                "variant {name:?} produced a different fingerprint"
            );
        }
    }

    #[test]
    fn the_canonical_form_is_one_representation_and_a_strict_reader_accepts_it() {
        let canonical = normalize_certificate_pem(CLEAN).unwrap();
        for (name, candidate) in filthy_variants() {
            let normalized = normalize_certificate_pem(&candidate).unwrap();
            assert_eq!(
                normalized.pem(),
                canonical.pem(),
                "variant {name:?} stored a second representation of one certificate"
            );
        }
        // The whole point of canonicalising before storage: whatever comes back out parses.
        assert!(Certificate::from_pem(canonical.pem().as_bytes()).is_ok());
        assert!(canonical.pem().starts_with(BEGIN_CERTIFICATE));
        assert!(canonical.pem().ends_with("-----END CERTIFICATE-----\n"));
        // Renormalising the canonical form is a no-op, so storage cannot drift on a re-save.
        let again = normalize_certificate_pem(canonical.pem()).unwrap();
        assert_eq!(again.pem(), canonical.pem());
        assert_eq!(again.removed_characters(), 0);
    }

    #[test]
    fn the_ignorable_characters_are_counted_and_reported_rather_than_hidden() {
        let (_, one_line) = filthy_variants()
            .into_iter()
            .find(|(name, _)| *name == "one-line")
            .unwrap();
        assert_eq!(
            normalize_certificate_pem(&one_line)
                .unwrap()
                .removed_characters(),
            0
        );

        let (_, nulls) = filthy_variants()
            .into_iter()
            .find(|(name, _)| *name == "embedded-nul-and-c0-controls")
            .unwrap();
        // Two control characters plus the line breaks the body was wrapped with.
        assert!(
            normalize_certificate_pem(&nulls)
                .unwrap()
                .removed_characters()
                >= 2
        );
    }

    #[test]
    fn a_character_that_would_change_the_bytes_is_refused_by_name_rather_than_dropped() {
        let body = body_of(CLEAN);
        // A word processor turning the first character into a curly quote. It sits WHERE a base64
        // character belongs, so dropping it would shorten the body and decode to other bytes.
        let corrupted = format!(
            "{BEGIN_CERTIFICATE}\n\u{201C}{}\n{END_CERTIFICATE}\n",
            &body[1..],
        );
        match normalize_certificate_pem(&corrupted) {
            Err(CertificatePemError::IllegalCharacter { character, offset }) => {
                assert_eq!(character, "U+201C");
                assert_eq!(&corrupted[offset..offset + 3], "\u{201C}");
            }
            other => panic!("a smart quote must be refused by name, got {other:?}"),
        }
    }

    #[test]
    fn each_structural_defect_is_named_and_none_is_repaired() {
        let body = body_of(CLEAN);

        assert_eq!(
            normalize_certificate_pem("   \n\t\u{FEFF}\n").unwrap_err(),
            CertificatePemError::Empty
        );
        // No armour: NOT synthesised around the body, even though the body alone would decode.
        assert_eq!(
            normalize_certificate_pem(&body).unwrap_err(),
            CertificatePemError::ArmourMissing
        );
        assert_eq!(
            normalize_certificate_pem("nothing to see here").unwrap_err(),
            CertificatePemError::ArmourMissing
        );
        // Em dashes for the armour dashes — a word-processor autocorrect, and unrecoverable.
        assert_eq!(
            normalize_certificate_pem(&format!("—BEGIN CERTIFICATE—\n{body}\n—END CERTIFICATE—"))
                .unwrap_err(),
            CertificatePemError::ArmourMissing
        );
        assert_eq!(
            normalize_certificate_pem(&format!("{BEGIN_CERTIFICATE}\n{body}\n")).unwrap_err(),
            CertificatePemError::EndArmourMissing
        );
        // A private key must never be quietly accepted into a field that holds a public certificate.
        assert_eq!(
            normalize_certificate_pem(
                "-----BEGIN PRIVATE KEY-----\nMAoCAQE=\n-----END PRIVATE KEY-----\n"
            )
            .unwrap_err(),
            CertificatePemError::WrongLabel {
                label: "PRIVATE KEY".to_owned()
            }
        );
        // A chain: refused, never silently reduced to its first element.
        assert_eq!(
            normalize_certificate_pem(&format!("{CLEAN}{CLEAN}")).unwrap_err(),
            CertificatePemError::MultipleBlocks { count: 2 }
        );
        // A truncated body: valid alphabet, invalid length. Not re-padded.
        assert!(matches!(
            normalize_certificate_pem(&format!(
                "{BEGIN_CERTIFICATE}\n{}\n{END_CERTIFICATE}\n",
                &body[..body.len() - 3]
            )),
            Err(CertificatePemError::Base64Invalid { .. })
        ));
        // Decodes cleanly, and is not a certificate.
        assert!(matches!(
            normalize_certificate_pem(&format!("{BEGIN_CERTIFICATE}\nZm9v\n{END_CERTIFICATE}\n")),
            Err(CertificatePemError::NotACertificate { .. })
        ));
    }
}
