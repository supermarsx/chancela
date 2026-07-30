//! Normalising the pasted AMA field-encryption key material, and refusing the rest by name.
//!
//! # Why this exists
//!
//! `ama_cert_pem` is filled by an operator pasting a block of text. Real paste is dirty: CRLF from
//! Windows, a UTF-8 BOM, trailing spaces on every line, a stray NUL from a terminal capture,
//! non-breaking spaces and zero-width characters from a word processor, no trailing newline, or the
//! whole block collapsed onto one line. The RFC 7468 reader behind
//! [`crate::FieldEncryptor::from_ama_key_pem`] is strict, so most of that made perfectly good key
//! material unusable with a message that named none of it.
//!
//! # Two armours, one key
//!
//! Field encryption needs exactly one thing: AMA's **RSA public key**. An X.509 certificate carries
//! one inside its `SubjectPublicKeyInfo`, and a `-----BEGIN PUBLIC KEY-----` block *is* a
//! `SubjectPublicKeyInfo`. Both are accepted, and both are reduced to the same
//! [`spki_der`](NormalizedAmaKeyPem::spki_der) — so the two inputs cannot disagree about which key
//! they carry. What they differ in is everything *around* the key: a certificate also names a
//! subject, an issuer and a validity window, and a bare public key names none of them. That
//! difference is reported, never papered over — see [`AmaKeyPemKind`].
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
//! where a slash should be, an en dash in the armour, a mangled `BEGIN` line, two blocks where one
//! was expected: each of those is a real difference between what the operator has and what they
//! meant to have. Guessing a repair would produce key material nobody chose, and the failure would
//! only surface later as a production request that encrypts a citizen's PIN to the wrong key. Every
//! one of them returns a [`CertificatePemError`] variant that names it.
//!
//! A `-----BEGIN RSA PUBLIC KEY-----` block is the one refusal that exists to *teach* rather than to
//! protect bytes: it is PKCS#1, the modulus and exponent with no algorithm identifier around them,
//! and it is not a `SubjectPublicKeyInfo`. It is held one conversion away from what this field
//! takes, so it is refused by its own name with that conversion in the sentence, rather than
//! collapsing into "malformed".
//!
//! # What "canonical" means here
//!
//! [`normalize_ama_key_pem`] does not hand back the operator's text with the whitespace tidied. It
//! decodes to DER, checks that the DER really is what its armour claims, and then **re-emits the PEM
//! from those verified bytes**: one `BEGIN` line, base64 wrapped at 64 columns, one `END` line, one
//! trailing newline. That is not a repair — the output is a function of the decoded bytes and the
//! label and nothing else, so it cannot differ from the input in anything but layout, and
//! [`NormalizedAmaKeyPem::der`] is the proof. It is what makes the one-line paste work without a
//! single guess, and it means there is exactly one stored representation of any given input.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Decode;
use der::Encode;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_cert::Certificate;
use x509_cert::spki::SubjectPublicKeyInfoRef;

use crate::error::CmdError;

/// The armour of a full X.509 certificate.
const CERTIFICATE_LABEL: &str = "CERTIFICATE";
/// The armour of a bare `SubjectPublicKeyInfo` — the same structure a certificate carries inside.
const PUBLIC_KEY_LABEL: &str = "PUBLIC KEY";
/// PKCS#1 `RSAPublicKey`. Accepted by nothing here, and refused by name rather than as noise.
const PKCS1_PUBLIC_KEY_LABEL: &str = "RSA PUBLIC KEY";
/// The prefix every RFC 7468 opening boundary shares, used to find blocks of *any* label.
const BEGIN_PREFIX: &str = "-----BEGIN ";
/// The boundary terminator, used to read a block's label back out.
const BOUNDARY_DASHES: &str = "-----";
/// Column width the canonical output wraps base64 at (RFC 7468 §2).
const PEM_LINE_WIDTH: usize = 64;

/// Which armour the operator supplied, and therefore what can be established about it.
///
/// This is not decoration. The two forms carry the **same key** and a different amount of
/// surrounding fact: a certificate names a subject, an issuer and a validity window; a bare public
/// key names none of them, because it has none to name. Everything that reports on this input has to
/// be able to say which it got, so that "no subject" reads as *there is no subject in this input*
/// rather than *the subject could not be read*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmaKeyPemKind {
    /// A full X.509 certificate; the key was taken from its `SubjectPublicKeyInfo`.
    Certificate,
    /// A bare `SubjectPublicKeyInfo`, which is the key and nothing else.
    PublicKey,
}

impl AmaKeyPemKind {
    /// The PEM label this kind arrives under.
    pub const fn label(self) -> &'static str {
        match self {
            AmaKeyPemKind::Certificate => CERTIFICATE_LABEL,
            AmaKeyPemKind::PublicKey => PUBLIC_KEY_LABEL,
        }
    }

    /// The stable machine identifier for this kind, as it travels to a client.
    ///
    /// `snake_case` and never translated: it is a wire discriminant, and the sentence a client
    /// renders around it is chosen by this value rather than parsed out of it.
    pub const fn as_str(self) -> &'static str {
        match self {
            AmaKeyPemKind::Certificate => "certificate",
            AmaKeyPemKind::PublicKey => "public_key",
        }
    }
}

/// Why a candidate PEM could not be turned into usable key material.
///
/// Each variant names one specific thing that was wrong, because "invalid certificate" tells an
/// operator holding a 2 KiB block of base64 nothing they can act on. The API layer maps these onto
/// stable diagnostic codes so the sentence an operator reads is in their own language.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CertificatePemError {
    /// Nothing but whitespace and invisible characters was supplied.
    #[error("no certificate or public key was supplied")]
    Empty,

    /// No `-----BEGIN <label>-----` boundary at all. Typically a truncated copy, or armour whose
    /// dashes a word processor replaced with a dash character that is not `-`.
    #[error(
        "no PEM armour was found: the text must contain a line reading exactly \
         \"-----BEGIN {CERTIFICATE_LABEL}-----\" or \"-----BEGIN {PUBLIC_KEY_LABEL}-----\""
    )]
    ArmourMissing,

    /// An opening boundary was found but the matching closing one was not. The label is carried so
    /// the sentence names the `END` line the operator is actually missing, not a guess at which
    /// armour they meant.
    #[error("the \"-----BEGIN {label}-----\" line has no matching \"-----END {label}-----\" line")]
    EndArmourMissing {
        /// The label read from the opening boundary, verbatim.
        label: String,
    },

    /// The block is PEM, and is neither of the two things this field takes.
    ///
    /// Says what was pasted and what is wanted, and nothing else. It deliberately does NOT mention
    /// private keys: this arm is reached by a `DH PARAMETERS` block as readily as by anything else,
    /// and warning an operator about private keys when they pasted something else reads as an
    /// accusation and as evidence the product misread them. That warning lives on
    /// [`CertificatePemError::PrivateKey`], which fires only when the input really is one.
    #[error(
        "the text is a PEM block labelled \"{label}\", not \"{CERTIFICATE_LABEL}\" or \
         \"{PUBLIC_KEY_LABEL}\"; this field takes AMA's field-encryption key, as either a public \
         certificate or the public key on its own"
    )]
    WrongLabel {
        /// The label read from between the boundary dashes, verbatim.
        label: String,
    },

    /// A PRIVATE key, in any of its armours.
    ///
    /// Split out of [`CertificatePemError::WrongLabel`] because it is not merely the wrong object:
    /// it is secret material pasted into a field for public material, and the text has already left
    /// the operator's machine by the time this is read. Saying so plainly is the whole point — a
    /// refusal that called it "the wrong label" would let a real exposure pass as a typo.
    #[error(
        "the text is a PEM block labelled \"{label}\", which is a PRIVATE key. This field takes \
         public material only — AMA's certificate, or its public key. The value was refused and \
         not stored; if it is a real private key, treat it as exposed and rotate it"
    )]
    PrivateKey {
        /// The label read from between the boundary dashes, verbatim.
        label: String,
    },

    /// A PKCS#1 `RSAPublicKey`, which is one conversion short of what this field takes.
    ///
    /// Separated from [`CertificatePemError::WrongLabel`] on purpose. An operator holding one of
    /// these has the right key in the wrong container, and "not a CERTIFICATE" would send them
    /// looking for a different file. What they need is the encoding difference and the command that
    /// closes it.
    #[error(
        "the text is a PEM block labelled \"{PKCS1_PUBLIC_KEY_LABEL}\", which is a PKCS#1 \
         RSAPublicKey: the modulus and exponent alone, with no algorithm identifier around them. \
         This field takes a SubjectPublicKeyInfo — the structure a \"{PUBLIC_KEY_LABEL}\" block \
         carries and a certificate holds inside it. Convert it with \
         `openssl rsa -RSAPublicKey_in -in key.pem -pubout`"
    )]
    Pkcs1PublicKey,

    /// More than one PEM block — a chain, or a certificate with its key pasted after it. Refused
    /// rather than resolved: choosing one of them would be choosing for the operator.
    ///
    /// The labels are listed because "2 blocks" and "a certificate and a private key" call for
    /// completely different actions, and the second is how an operator discovers they pasted a
    /// secret they did not mean to.
    #[error(
        "the text contains {count} PEM blocks ({}); paste exactly one certificate or one public \
         key, not a chain or a bundle",
        .labels.join(", ")
    )]
    MultipleBlocks {
        /// How many opening boundaries were counted.
        count: usize,
        /// The distinct labels found, in order of first appearance, capped for display.
        labels: Vec<String>,
    },

    /// A character inside the base64 body that is neither base64 nor ignorable whitespace. This is
    /// the smart-quote and mangled-character case, and it is where the "normalise, never repair"
    /// line is actually drawn: dropping it or guessing at what it replaced would change the key this
    /// block is trusted to carry.
    #[error(
        "the PEM body contains {character} at byte offset {offset}, which is neither \
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
    #[error("the PEM body is not valid base64: {detail}")]
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

    /// The bytes decoded, and are not a `SubjectPublicKeyInfo`.
    ///
    /// The `PUBLIC KEY` twin of [`CertificatePemError::NotACertificate`], and separate from it for
    /// the same reason the labels are separate: an operator whose `PUBLIC KEY` block does not decode
    /// must not be told their *certificate* is broken.
    #[error("the decoded bytes are not a SubjectPublicKeyInfo public key: {detail}")]
    NotAPublicKey {
        /// The DER reader's own message.
        detail: String,
    },
}

impl From<CertificatePemError> for CmdError {
    fn from(err: CertificatePemError) -> Self {
        CmdError::Encryption(err.to_string())
    }
}

/// Key material that parsed, together with the bytes that prove what it is.
///
/// [`der`](Self::der) is the whole point: it is the decoded block, and every other member is derived
/// from it. Two inputs that normalise to the same `der` are the same object however differently they
/// were pasted.
///
/// [`spki_der`](Self::spki_der) is the narrower fact and the more useful one: it is the
/// `SubjectPublicKeyInfo` **in both forms**, so a certificate and the bare public key extracted from
/// it produce identical bytes here. That is what makes
/// [`public_key_sha256_fingerprint`](Self::public_key_sha256_fingerprint) the one value an operator
/// can compare across the two input forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedAmaKeyPem {
    kind: AmaKeyPemKind,
    pem: String,
    der: Vec<u8>,
    spki_der: Vec<u8>,
    removed_characters: usize,
}

impl NormalizedAmaKeyPem {
    /// Which of the two accepted armours this came from.
    pub fn kind(&self) -> AmaKeyPemKind {
        self.kind
    }

    /// The canonical PEM: `BEGIN`, base64 of [`der`](Self::der) wrapped at 64 columns, `END`, one
    /// trailing newline — under the label this input actually carried. This is the form that should
    /// be stored, so the value later handed to a strict reader is already one a strict reader
    /// accepts.
    pub fn pem(&self) -> &str {
        &self.pem
    }

    /// The decoded bytes of the block as supplied: a certificate's DER, or a `SubjectPublicKeyInfo`.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The `SubjectPublicKeyInfo` DER, whichever armour arrived.
    ///
    /// For [`AmaKeyPemKind::PublicKey`] this is [`der`](Self::der) itself; for
    /// [`AmaKeyPemKind::Certificate`] it is the certificate's `subject_public_key_info`, re-encoded.
    /// It is the only thing field encryption consumes, which is why the two input forms provably
    /// reach the same key.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// The certificate's DER, or `None` when a bare public key was supplied.
    ///
    /// `None` means *this input carries no certificate*, not *the certificate could not be read* —
    /// a block that claimed to be a certificate and failed to decode never gets this far.
    pub fn certificate_der(&self) -> Option<&[u8]> {
        match self.kind {
            AmaKeyPemKind::Certificate => Some(&self.der),
            AmaKeyPemKind::PublicKey => None,
        }
    }

    /// How many *unexpected* ignorable characters the body carried.
    ///
    /// Line breaks are excluded: wrapping the base64 across lines is what PEM looks like, and
    /// counting it would make every ordinary block look as though it had been cleaned up. What this
    /// counts is the rest — trailing spaces, tabs, a no-break space, a stray NUL, a zero-width
    /// character. Reported rather than swallowed: an operator is entitled to know the text they
    /// pasted was not the text that was read, even when the difference provably could not change the
    /// decoded bytes.
    pub fn removed_characters(&self) -> usize {
        self.removed_characters
    }

    /// SHA-256 of the `SubjectPublicKeyInfo`, as 64 lowercase hex characters.
    ///
    /// **The value that is the same for both input forms.** A certificate and the `PUBLIC KEY` block
    /// extracted from it fingerprint identically here, because it is computed over the key material
    /// and not over the document wrapped around it. It is therefore the one fingerprint that answers
    /// "is this the same key I was given?" regardless of which artefact the operator was handed.
    ///
    /// It is deliberately over the DER and not over the PEM text: a fingerprint that moved when
    /// somebody re-wrapped the base64 would be useless for the one job it has.
    pub fn public_key_sha256_fingerprint(&self) -> String {
        hex_sha256(&self.spki_der)
    }

    /// SHA-256 of the certificate's DER, or `None` when a bare public key was supplied.
    ///
    /// A different value from [`public_key_sha256_fingerprint`](Self::public_key_sha256_fingerprint)
    /// for the same key, and the two must never be presented as interchangeable: this is the number
    /// `openssl x509 -fingerprint -sha256` prints and the one a certificate-issuing authority
    /// publishes, and it exists only when there is a certificate to compute it over.
    pub fn certificate_sha256_fingerprint(&self) -> Option<String> {
        self.certificate_der().map(hex_sha256)
    }
}

/// SHA-256 of `bytes` as 64 lowercase hex characters — the same shape the trust-anchor fingerprints
/// in the signing settings use, so the two are comparable by eye.
fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("high nibble < 16"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("low nibble < 16"));
    }
    out
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
///   and web pages rather than by anything that produced the key material.
///
/// Everything else is refused. Note what is NOT here: a curly quote, an en dash, a Cyrillic letter
/// that looks like a Latin one. Those are outside the alphabet too, but they sit where a real base64
/// character was, so removing them would silently shorten the body and decode to different bytes.
fn is_ignorable_in_body(c: char) -> bool {
    c.is_whitespace()
        || c.is_control()
        || matches!(c, '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}')
}

/// Normalise pasted AMA key material, verify it, and return the canonical form — or say what is
/// wrong.
///
/// Accepts a `CERTIFICATE` block or a bare `PUBLIC KEY` block, and reduces both to one
/// [`NormalizedAmaKeyPem::spki_der`]. The order is fixed and is the contract: **normalise the safe
/// classes, then verify, then refuse.** Nothing is repaired between the second and third steps.
///
/// # Errors
///
/// Every [`CertificatePemError`] variant, each naming one specific defect. A certificate that is
/// merely *expired* is not an error here — that is a determinable fact about a perfectly well-formed
/// certificate, and it is the caller's to report.
pub fn normalize_ama_key_pem(input: &str) -> Result<NormalizedAmaKeyPem, CertificatePemError> {
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
        count => {
            return Err(CertificatePemError::MultipleBlocks {
                count,
                labels: distinct_labels_for_display(&labels),
            });
        }
    }
    let label = labels[0].as_str();
    let kind = match label {
        CERTIFICATE_LABEL => AmaKeyPemKind::Certificate,
        PUBLIC_KEY_LABEL => AmaKeyPemKind::PublicKey,
        // One conversion away from usable, so it is told that rather than lumped in below.
        PKCS1_PUBLIC_KEY_LABEL => return Err(CertificatePemError::Pkcs1PublicKey),
        // Secret material in a field for public material: its own refusal, checked before the
        // generic one so it can never degrade into "wrong label".
        other if is_private_key_label(other) => {
            return Err(CertificatePemError::PrivateKey {
                label: other.to_owned(),
            });
        }
        other => {
            return Err(CertificatePemError::WrongLabel {
                label: other.to_owned(),
            });
        }
    };

    // The label is one of the two, so the exact opening boundary is present by construction.
    let begin = begin_boundary(label);
    let end = end_boundary(label);
    let begin_at = text
        .find(&begin)
        .ok_or(CertificatePemError::ArmourMissing)?;
    let body_start = begin_at + begin.len();
    let body_len =
        text[body_start..]
            .find(&end)
            .ok_or_else(|| CertificatePemError::EndArmourMissing {
                label: label.to_owned(),
            })?;
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
    // are what their armour says, so nothing downstream can be handed a tidy-looking block of
    // nonsense. Both arms end at the SAME SubjectPublicKeyInfo, which is the whole reason the two
    // armours can be accepted interchangeably.
    let spki_der = match kind {
        AmaKeyPemKind::Certificate => {
            let certificate =
                Certificate::from_der(&der).map_err(|e| CertificatePemError::NotACertificate {
                    detail: e.to_string(),
                })?;
            certificate
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|e| CertificatePemError::NotACertificate {
                    detail: format!("its subject public key info could not be re-encoded: {e}"),
                })?
        }
        AmaKeyPemKind::PublicKey => {
            SubjectPublicKeyInfoRef::from_der(&der).map_err(|e| {
                CertificatePemError::NotAPublicKey {
                    detail: e.to_string(),
                }
            })?;
            der.clone()
        }
    };

    Ok(NormalizedAmaKeyPem {
        kind,
        pem: canonical_pem(label, &der),
        der,
        spki_der,
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

/// Whether a PEM label names a private key, in any of the armours one arrives under.
///
/// Matched by suffix rather than by an enumerated list, so `PRIVATE KEY`, `RSA PRIVATE KEY`,
/// `EC PRIVATE KEY`, `DSA PRIVATE KEY`, `ENCRYPTED PRIVATE KEY` and `OPENSSH PRIVATE KEY` all land
/// on the loud refusal. A list would have to be complete to be safe, and the one thing worse than
/// refusing a private key vaguely is refusing an unlisted one vaguely.
fn is_private_key_label(label: &str) -> bool {
    label == "PRIVATE KEY" || label.ends_with(" PRIVATE KEY")
}

/// How many distinct labels a multi-block refusal lists before it stops.
///
/// The input is bounded but not small, and a hostile paste can carry thousands of `BEGIN` lines.
/// Five is enough to tell "a chain" from "a certificate and a private key", which is the only
/// distinction this list exists to draw.
const MAX_LISTED_LABELS: usize = 5;

/// The distinct labels of a multi-block paste, in order of first appearance and capped.
fn distinct_labels_for_display(labels: &[String]) -> Vec<String> {
    let mut distinct: Vec<String> = Vec::new();
    for label in labels {
        if distinct.len() == MAX_LISTED_LABELS {
            distinct.push("…".to_owned());
            break;
        }
        if !distinct.iter().any(|seen| seen == label) {
            distinct.push(label.clone());
        }
    }
    distinct
}

/// The full opening boundary for `label`.
fn begin_boundary(label: &str) -> String {
    format!("{BEGIN_PREFIX}{label}{BOUNDARY_DASHES}")
}

/// The full closing boundary for `label`.
fn end_boundary(label: &str) -> String {
    format!("-----END {label}{BOUNDARY_DASHES}")
}

/// Emit RFC 7468 PEM for `der` under `label`. A pure function of its two inputs — that is what makes
/// it canonical.
fn canonical_pem(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut out = String::with_capacity(body.len() + body.len() / PEM_LINE_WIDTH + 64);
    out.push_str(&begin_boundary(label));
    out.push('\n');
    for chunk in body.as_bytes().chunks(PEM_LINE_WIDTH) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 output is ASCII"));
        out.push('\n');
    }
    out.push_str(&end_boundary(label));
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::DecodePem;

    const CLEAN: &str = include_str!("../fixtures/ama_encryption_cert.pem");
    /// The SAME key as [`CLEAN`], in the other accepted armour — `openssl x509 -noout -pubkey` of it.
    const CLEAN_PUBLIC_KEY: &str = include_str!("../fixtures/ama_encryption_public_key.pem");
    /// Both armours as they arrive out of an indented document: six spaces before EVERY line,
    /// including the `BEGIN` and `END` lines.
    const INDENTED_CERT: &str = include_str!("../fixtures/ama_encryption_cert_indented.pem");
    const INDENTED_PUBLIC_KEY: &str =
        include_str!("../fixtures/ama_encryption_public_key_indented.pem");

    const BEGIN_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";
    const END_CERTIFICATE: &str = "-----END CERTIFICATE-----";
    const BEGIN_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----";
    const END_PUBLIC_KEY: &str = "-----END PUBLIC KEY-----";

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

    /// The fixture's SubjectPublicKeyInfo, taken WITHOUT this module — the independent reference the
    /// `PUBLIC KEY` armour is measured against.
    fn reference_spki_der() -> Vec<u8> {
        Certificate::from_pem(CLEAN.as_bytes())
            .expect("the fixture is a certificate")
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("its spki re-encodes")
    }

    /// The fixture's key as an operator would have been handed it: a bare `PUBLIC KEY` block.
    fn reference_public_key_pem() -> String {
        let body = STANDARD.encode(reference_spki_der());
        let mut out = String::from(BEGIN_PUBLIC_KEY);
        out.push('\n');
        for chunk in body.as_bytes().chunks(PEM_LINE_WIDTH) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str(END_PUBLIC_KEY);
        out.push('\n');
        out
    }

    /// The body of a PEM block, with every line break removed.
    fn body_of(pem: &str, begin: &str, end: &str) -> String {
        let start = pem.find(begin).unwrap() + begin.len();
        let len = pem[start..].find(end).unwrap();
        pem[start..start + len]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    }

    /// Every way the same block can arrive, and they must all be the same block.
    ///
    /// Parameterised over the armour so the `PUBLIC KEY` path gets the identical dirt battery rather
    /// than a thinner one written by hand. Named so a failure says which dirt class broke, rather
    /// than "case 4".
    fn filthy_variants(clean: &str, begin: &str, end: &str) -> Vec<(&'static str, String)> {
        let body = body_of(clean, begin, end);
        let wrapped: Vec<&str> = body
            .as_bytes()
            .chunks(PEM_LINE_WIDTH)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();

        vec![
            ("crlf", clean.replace('\n', "\r\n")),
            ("bare-cr", clean.replace('\n', "\r")),
            ("utf8-bom", format!("\u{FEFF}{clean}")),
            (
                "trailing-spaces-on-every-line",
                clean
                    .lines()
                    .map(|line| format!("{line}   \n"))
                    .collect::<String>(),
            ),
            // Leading whitespace on every line, ARMOUR LINES INCLUDED. This is what a paste out of
            // an indented document, a YAML block scalar or a chat window actually looks like, and it
            // is safe on exactly the same grounds as the trailing kind: base64 has no meaning for a
            // space, so the decoded DER provably cannot move. Anything that scanned for a line
            // *starting* with `-----BEGIN` would reject this while the bytes are perfectly good.
            (
                "every-line-indented",
                clean
                    .lines()
                    .map(|line| format!("      {line}\n"))
                    .collect::<String>(),
            ),
            (
                "indented-with-tabs-and-crlf",
                clean
                    .lines()
                    .map(|line| format!("\t\t{line}\r\n"))
                    .collect::<String>(),
            ),
            ("no-trailing-newline", clean.trim_end().to_owned()),
            ("extra-trailing-newlines", format!("{clean}\n\n\n")),
            ("one-line", format!("{begin}{body}{end}")),
            (
                "embedded-nul-and-c0-controls",
                format!(
                    "{begin}\n{}\0{}\u{0007}\n{end}\n",
                    wrapped[0],
                    wrapped[1..].join("\n"),
                ),
            ),
            (
                "non-breaking-and-zero-width-spaces",
                format!(
                    "{begin}\n{}\u{00A0}\u{200B}\n{}\u{FEFF}\n{end}\n",
                    wrapped[0],
                    wrapped[1..].join("\n"),
                ),
            ),
            (
                "explanatory-text-around-the-block",
                format!(
                    "subject=CN = AMA\nissuer=CN = AMA\n{}\nNotes pasted after the block.\n",
                    clean.trim_end(),
                ),
            ),
            (
                "everything-at-once",
                format!("\u{FEFF}subject=CN = AMA\r\n{begin}\r\n{body}\u{00A0}\0\r\n{end}"),
            ),
        ]
    }

    #[test]
    fn a_clean_certificate_normalises_to_exactly_what_a_strict_reader_decoded() {
        let normalized = normalize_ama_key_pem(CLEAN).expect("the fixture must normalise");
        assert_eq!(normalized.kind(), AmaKeyPemKind::Certificate);
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

    /// The load-bearing equivalence: two armours, one key.
    ///
    /// A certificate and the `PUBLIC KEY` block carved out of it must reach byte-identical
    /// `spki_der`, and therefore one public-key fingerprint. If this ever fails, the two accepted
    /// inputs have stopped meaning the same thing and one of them is encrypting to a different key.
    #[test]
    fn a_certificate_and_the_public_key_inside_it_reach_the_same_key() {
        let from_certificate = normalize_ama_key_pem(CLEAN).unwrap();
        let from_public_key = normalize_ama_key_pem(&reference_public_key_pem()).unwrap();

        assert_eq!(from_public_key.kind(), AmaKeyPemKind::PublicKey);
        assert_eq!(from_certificate.spki_der(), from_public_key.spki_der());
        assert_eq!(from_certificate.spki_der(), reference_spki_der().as_slice());
        assert_eq!(
            from_certificate.public_key_sha256_fingerprint(),
            from_public_key.public_key_sha256_fingerprint(),
        );

        // And the two are still told apart where they genuinely differ.
        assert_eq!(from_public_key.der(), from_public_key.spki_der());
        assert!(from_public_key.certificate_der().is_none());
        assert!(from_public_key.certificate_sha256_fingerprint().is_none());
        assert!(from_certificate.certificate_der().is_some());
        assert_ne!(
            from_certificate.certificate_sha256_fingerprint(),
            Some(from_certificate.public_key_sha256_fingerprint()),
            "the certificate and public-key fingerprints of one key must not collide, or the \
             panel's two rows would be indistinguishable"
        );
    }

    /// The `PUBLIC KEY` fixture on disk really is the key inside the certificate fixture.
    ///
    /// Without this the two fixtures could drift apart and every "both armours agree" test below
    /// would keep passing while comparing two different keys to themselves.
    #[test]
    fn the_public_key_fixture_is_the_key_inside_the_certificate_fixture() {
        let from_fixture = normalize_ama_key_pem(CLEAN_PUBLIC_KEY).expect("the fixture normalises");
        assert_eq!(from_fixture.kind(), AmaKeyPemKind::PublicKey);
        assert_eq!(from_fixture.spki_der(), reference_spki_der().as_slice());
        assert_eq!(from_fixture.pem(), reference_public_key_pem());
    }

    /// An indented paste — leading whitespace on every line, armour included — is the same input.
    ///
    /// This is a real shape, not a hypothetical: PEM copied out of a documentation page, a YAML
    /// block scalar or a chat message arrives with every line pushed right, and the `BEGIN` line
    /// goes with it. The fixtures are files rather than strings built here on purpose — a test that
    /// constructs its own indentation cannot catch a reader that mishandles a real file's line
    /// endings at the same time.
    #[test]
    fn a_paste_indented_on_every_line_normalises_for_both_armours() {
        for (name, indented, clean) in [
            ("certificate", INDENTED_CERT, CLEAN),
            ("public-key", INDENTED_PUBLIC_KEY, CLEAN_PUBLIC_KEY),
        ] {
            // The fixture really is indented, armour line included — otherwise this test proves
            // nothing and would keep passing if somebody "tidied" the file.
            assert!(
                indented.starts_with("      -----BEGIN "),
                "the {name} fixture must be indented on its BEGIN line"
            );
            assert!(
                indented
                    .lines()
                    .all(|line| line.is_empty() || line.starts_with("      ")),
                "every line of the {name} fixture must be indented"
            );

            let reference = normalize_ama_key_pem(clean)
                .unwrap_or_else(|e| panic!("the clean {name} fixture must normalise: {e}"));
            let normalized = normalize_ama_key_pem(indented)
                .unwrap_or_else(|e| panic!("the indented {name} fixture must normalise: {e}"));

            assert_eq!(normalized.kind(), reference.kind(), "{name}");
            assert_eq!(normalized.der(), reference.der(), "{name}");
            assert_eq!(normalized.spki_der(), reference.spki_der(), "{name}");
            assert_eq!(normalized.pem(), reference.pem(), "{name}");
            assert_eq!(
                normalized.public_key_sha256_fingerprint(),
                reference.public_key_sha256_fingerprint(),
                "{name}"
            );
            // The indentation is DISCLOSED, not swallowed: the operator is told the text they
            // pasted was not the text that was read, even though it provably could not change the
            // decoded bytes.
            assert!(
                normalized.removed_characters() > 0,
                "{name}: the stripped indentation must be reported"
            );
        }
    }

    #[test]
    fn every_filthy_variant_yields_byte_identical_der_and_one_fingerprint() {
        for (clean, begin, end) in [
            (CLEAN.to_owned(), BEGIN_CERTIFICATE, END_CERTIFICATE),
            (reference_public_key_pem(), BEGIN_PUBLIC_KEY, END_PUBLIC_KEY),
        ] {
            let reference = normalize_ama_key_pem(&clean).unwrap();
            let expected_fingerprint = reference.public_key_sha256_fingerprint();
            assert_eq!(expected_fingerprint.len(), 64);

            for (name, candidate) in filthy_variants(&clean, begin, end) {
                let normalized = normalize_ama_key_pem(&candidate)
                    .unwrap_or_else(|e| panic!("variant {name:?} of {begin} must normalise: {e}"));
                assert_eq!(
                    normalized.der(),
                    reference.der(),
                    "variant {name:?} of {begin} decoded to different bytes"
                );
                assert_eq!(normalized.kind(), reference.kind(), "variant {name:?}");
                assert_eq!(
                    normalized.public_key_sha256_fingerprint(),
                    expected_fingerprint,
                    "variant {name:?} of {begin} produced a different fingerprint"
                );
            }
        }
    }

    #[test]
    fn the_canonical_form_is_one_representation_and_a_strict_reader_accepts_it() {
        for (clean, begin, end) in [
            (CLEAN.to_owned(), BEGIN_CERTIFICATE, END_CERTIFICATE),
            (reference_public_key_pem(), BEGIN_PUBLIC_KEY, END_PUBLIC_KEY),
        ] {
            let canonical = normalize_ama_key_pem(&clean).unwrap();
            for (name, candidate) in filthy_variants(&clean, begin, end) {
                let normalized = normalize_ama_key_pem(&candidate).unwrap();
                assert_eq!(
                    normalized.pem(),
                    canonical.pem(),
                    "variant {name:?} of {begin} stored a second representation of one input"
                );
            }
            // The canonical form keeps the armour it arrived under — a certificate is not re-emitted
            // as a public key, which would silently discard the subject, issuer and dates.
            assert!(canonical.pem().starts_with(begin));
            assert!(canonical.pem().ends_with(&format!("{end}\n")));
            // Renormalising the canonical form is a no-op, so storage cannot drift on a re-save.
            let again = normalize_ama_key_pem(canonical.pem()).unwrap();
            assert_eq!(again.pem(), canonical.pem());
            assert_eq!(again.removed_characters(), 0);
        }
        // The whole point of canonicalising before storage: whatever comes back out parses.
        let canonical = normalize_ama_key_pem(CLEAN).unwrap();
        assert!(Certificate::from_pem(canonical.pem().as_bytes()).is_ok());
    }

    #[test]
    fn the_ignorable_characters_are_counted_and_reported_rather_than_hidden() {
        let variants = filthy_variants(CLEAN, BEGIN_CERTIFICATE, END_CERTIFICATE);
        let (_, one_line) = variants
            .iter()
            .find(|(name, _)| *name == "one-line")
            .unwrap();
        assert_eq!(
            normalize_ama_key_pem(one_line)
                .unwrap()
                .removed_characters(),
            0
        );

        let (_, nulls) = variants
            .iter()
            .find(|(name, _)| *name == "embedded-nul-and-c0-controls")
            .unwrap();
        // Two control characters plus the line breaks the body was wrapped with.
        assert!(normalize_ama_key_pem(nulls).unwrap().removed_characters() >= 2);
    }

    #[test]
    fn a_character_that_would_change_the_bytes_is_refused_by_name_rather_than_dropped() {
        let body = body_of(CLEAN, BEGIN_CERTIFICATE, END_CERTIFICATE);
        // A word processor turning the first character into a curly quote. It sits WHERE a base64
        // character belongs, so dropping it would shorten the body and decode to other bytes.
        let corrupted = format!(
            "{BEGIN_CERTIFICATE}\n\u{201C}{}\n{END_CERTIFICATE}\n",
            &body[1..],
        );
        match normalize_ama_key_pem(&corrupted) {
            Err(CertificatePemError::IllegalCharacter { character, offset }) => {
                assert_eq!(character, "U+201C");
                assert_eq!(&corrupted[offset..offset + 3], "\u{201C}");
            }
            other => panic!("a smart quote must be refused by name, got {other:?}"),
        }
    }

    #[test]
    fn each_structural_defect_is_named_and_none_is_repaired() {
        let body = body_of(CLEAN, BEGIN_CERTIFICATE, END_CERTIFICATE);

        assert_eq!(
            normalize_ama_key_pem("   \n\t\u{FEFF}\n").unwrap_err(),
            CertificatePemError::Empty
        );
        // No armour: NOT synthesised around the body, even though the body alone would decode.
        assert_eq!(
            normalize_ama_key_pem(&body).unwrap_err(),
            CertificatePemError::ArmourMissing
        );
        assert_eq!(
            normalize_ama_key_pem("nothing to see here").unwrap_err(),
            CertificatePemError::ArmourMissing
        );
        // Em dashes for the armour dashes — a word-processor autocorrect, and unrecoverable.
        assert_eq!(
            normalize_ama_key_pem(&format!("—BEGIN CERTIFICATE—\n{body}\n—END CERTIFICATE—"))
                .unwrap_err(),
            CertificatePemError::ArmourMissing
        );
        // The missing END line names the armour that was actually opened, for both labels.
        assert_eq!(
            normalize_ama_key_pem(&format!("{BEGIN_CERTIFICATE}\n{body}\n")).unwrap_err(),
            CertificatePemError::EndArmourMissing {
                label: CERTIFICATE_LABEL.to_owned()
            }
        );
        assert_eq!(
            normalize_ama_key_pem(&format!("{BEGIN_PUBLIC_KEY}\n{body}\n")).unwrap_err(),
            CertificatePemError::EndArmourMissing {
                label: PUBLIC_KEY_LABEL.to_owned()
            }
        );
        // A private key must never be quietly accepted into a field that holds public key material,
        // and it gets its OWN refusal rather than the generic wrong-label one.
        assert_eq!(
            normalize_ama_key_pem(
                "-----BEGIN PRIVATE KEY-----\nMAoCAQE=\n-----END PRIVATE KEY-----\n"
            )
            .unwrap_err(),
            CertificatePemError::PrivateKey {
                label: "PRIVATE KEY".to_owned()
            }
        );
        // Something that is neither: no private-key warning, because they pasted no private key.
        assert_eq!(
            normalize_ama_key_pem(
                "-----BEGIN DH PARAMETERS-----\nMAoCAQE=\n-----END DH PARAMETERS-----\n"
            )
            .unwrap_err(),
            CertificatePemError::WrongLabel {
                label: "DH PARAMETERS".to_owned()
            }
        );
        // A chain: refused, never silently reduced to its first element, and it says what of.
        assert_eq!(
            normalize_ama_key_pem(&format!("{CLEAN}{CLEAN}")).unwrap_err(),
            CertificatePemError::MultipleBlocks {
                count: 2,
                labels: vec!["CERTIFICATE".to_owned()],
            }
        );
        // A certificate with its own public key pasted after it is still two blocks.
        assert_eq!(
            normalize_ama_key_pem(&format!("{CLEAN}{}", reference_public_key_pem())).unwrap_err(),
            CertificatePemError::MultipleBlocks {
                count: 2,
                labels: vec!["CERTIFICATE".to_owned(), "PUBLIC KEY".to_owned()],
            }
        );
        // A truncated body: valid alphabet, invalid length. Not re-padded.
        assert!(matches!(
            normalize_ama_key_pem(&format!(
                "{BEGIN_CERTIFICATE}\n{}\n{END_CERTIFICATE}\n",
                &body[..body.len() - 3]
            )),
            Err(CertificatePemError::Base64Invalid { .. })
        ));
        // Decodes cleanly, and is not a certificate.
        assert!(matches!(
            normalize_ama_key_pem(&format!("{BEGIN_CERTIFICATE}\nZm9v\n{END_CERTIFICATE}\n")),
            Err(CertificatePemError::NotACertificate { .. })
        ));
        // The PUBLIC KEY twin: decodes cleanly, and is not a SubjectPublicKeyInfo. It must NOT be
        // reported as a broken certificate — the operator pasted no certificate.
        assert!(matches!(
            normalize_ama_key_pem(&format!("{BEGIN_PUBLIC_KEY}\nZm9v\n{END_PUBLIC_KEY}\n")),
            Err(CertificatePemError::NotAPublicKey { .. })
        ));
        // A whole certificate under PUBLIC KEY armour is not an SPKI, and says so.
        assert!(matches!(
            normalize_ama_key_pem(&format!("{BEGIN_PUBLIC_KEY}\n{body}\n{END_PUBLIC_KEY}\n")),
            Err(CertificatePemError::NotAPublicKey { .. })
        ));
    }

    /// PKCS#1 is refused, and the refusal explains the encoding rather than calling it malformed.
    ///
    /// An operator holding an `RSA PUBLIC KEY` block has the right key in the wrong container. Told
    /// "not a certificate", they go looking for a file that does not exist; told the difference,
    /// they run one `openssl` command.
    #[test]
    fn a_pkcs1_public_key_is_refused_by_name_with_the_difference_stated() {
        let block = "-----BEGIN RSA PUBLIC KEY-----\nMAoCAQE=\n-----END RSA PUBLIC KEY-----\n";
        let err = normalize_ama_key_pem(block).unwrap_err();
        assert_eq!(err, CertificatePemError::Pkcs1PublicKey);
        let message = err.to_string();
        // The three things the sentence has to carry: what they have, what is wanted, and the fix.
        assert!(message.contains("RSA PUBLIC KEY"), "{message}");
        assert!(message.contains("SubjectPublicKeyInfo"), "{message}");
        assert!(message.contains("openssl"), "{message}");
        assert!(
            !message.contains("malformed"),
            "a convertible key must not be called malformed: {message}"
        );
    }

    /// The refusal for an unaccepted label names BOTH armours that are accepted.
    ///
    /// Without this, an operator holding the bare public key reads "not a CERTIFICATE" and concludes
    /// their key is unusable — which is exactly the dead end this work exists to remove.
    #[test]
    fn the_wrong_label_refusal_names_both_accepted_armours() {
        let err = normalize_ama_key_pem(
            "-----BEGIN DH PARAMETERS-----\nMAoCAQE=\n-----END DH PARAMETERS-----\n",
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("CERTIFICATE"), "{message}");
        assert!(message.contains("PUBLIC KEY"), "{message}");
        assert!(message.contains("DH PARAMETERS"), "{message}");
        // And it does NOT lecture about private keys. They pasted a public parameter set; being
        // told about private keys reads as an accusation and as a misread of what they sent.
        assert!(
            !message.contains("PRIVATE"),
            "the generic refusal must not mention private keys: {message}"
        );

        let armour_missing = CertificatePemError::ArmourMissing.to_string();
        assert!(
            armour_missing.contains("BEGIN CERTIFICATE"),
            "{armour_missing}"
        );
        assert!(
            armour_missing.contains("BEGIN PUBLIC KEY"),
            "{armour_missing}"
        );
    }

    /// A private key is refused loudly, by that name, in every armour one arrives under.
    ///
    /// The text has already left the operator's machine by the time they read this — the inspection
    /// and the credential write both send it — so the refusal says so rather than filing it as a
    /// typo. That is the difference between a mistake an operator corrects and one they act on.
    #[test]
    fn a_private_key_is_refused_loudly_in_every_armour_it_arrives_under() {
        for label in [
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
        ] {
            let err = normalize_ama_key_pem(&format!(
                "-----BEGIN {label}-----\nMAoCAQE=\n-----END {label}-----\n"
            ))
            .unwrap_err();
            assert_eq!(
                err,
                CertificatePemError::PrivateKey {
                    label: label.to_owned()
                },
                "{label} must reach the private-key refusal, not the generic one"
            );
            let message = err.to_string();
            assert!(message.contains(label), "{message}");
            assert!(message.contains("PRIVATE key"), "{message}");
            assert!(message.contains("not stored"), "{message}");
            assert!(message.contains("rotate"), "{message}");
        }

        // `PUBLIC KEY` must not be dragged in by a sloppy substring test.
        assert!(!is_private_key_label(PUBLIC_KEY_LABEL));
        assert!(!is_private_key_label(CERTIFICATE_LABEL));
        assert!(!is_private_key_label("NOTPRIVATE KEY"));
    }

    /// A multi-block paste says WHAT was pasted, capped so a hostile input cannot flood the message.
    #[test]
    fn a_multi_block_refusal_lists_the_distinct_labels_and_stops() {
        let mixed =
            format!("{CLEAN}-----BEGIN PRIVATE KEY-----\nMAoCAQE=\n-----END PRIVATE KEY-----\n");
        let err = normalize_ama_key_pem(&mixed).unwrap_err();
        assert_eq!(
            err,
            CertificatePemError::MultipleBlocks {
                count: 2,
                labels: vec!["CERTIFICATE".to_owned(), "PRIVATE KEY".to_owned()],
            }
        );
        // The whole reason the labels are listed: this is how an operator learns their paste
        // carried a secret, instead of reading "2 PEM blocks" and deleting one at random.
        assert!(err.to_string().contains("PRIVATE KEY"), "{err}");

        // A flood is truncated rather than rendered in full.
        let flood: String = (0..50)
            .map(|i| format!("-----BEGIN LABEL{i}-----\nZm9v\n-----END LABEL{i}-----\n"))
            .collect();
        match normalize_ama_key_pem(&flood).unwrap_err() {
            CertificatePemError::MultipleBlocks { count, labels } => {
                assert_eq!(count, 50);
                assert_eq!(labels.len(), MAX_LISTED_LABELS + 1);
                assert_eq!(labels.last().map(String::as_str), Some("…"));
            }
            other => panic!("a flood is a multi-block refusal, got {other:?}"),
        }
    }
}
