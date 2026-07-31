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
///
/// `pub(crate)` because the **response** side — [`normalize_response_cert_chain`] — draws the exact
/// same line: this one predicate is the entire safety argument for stripping preamble and body junk
/// without ever changing the decoded DER, and the two directions must not disagree about where it
/// falls.
pub(crate) fn is_ignorable_in_body(c: char) -> bool {
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

// --- The response side: GetCertificate's certificate chain ----------------------------------------
//
// Everything above governs the *input* an operator pastes into `ama_cert_pem`. What follows governs
// the *response* AMA's `GetCertificate` returns: a PEM string carrying one or more concatenated
// `CERTIFICATE` blocks (the citizen's leaf and its issuer chain). It is a different problem — a chain
// is the expected, correct shape here, not a refusal — but it turns on the same distinction, so it
// reuses [`is_ignorable_in_body`] rather than a second copy that could drift from it.

/// The exact opening boundary of a response certificate block.
const BEGIN_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";
/// The exact closing boundary of a response certificate block.
const END_CERTIFICATE: &str = "-----END CERTIFICATE-----";

/// Why the certificate chain returned by `GetCertificate` could not be read.
///
/// Kept separate from [`CertificatePemError`] on purpose. That type governs the operator's pasted
/// input, where a second block is a mistake to be refused by name; this governs AMA's response,
/// where several blocks are the whole point. The one thing the two share is the line
/// [`is_ignorable_in_body`] draws, and each names its own defects because the actions they call for
/// are different.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CertificateChainError {
    /// Not a single `-----BEGIN CERTIFICATE-----` block was present.
    #[error("the GetCertificate response contained no \"-----BEGIN CERTIFICATE-----\" block")]
    NoCertificates,

    /// A block opened and never closed. The offset locates the unmatched `BEGIN`.
    #[error(
        "a \"-----BEGIN CERTIFICATE-----\" at byte offset {offset} has no matching \
         \"-----END CERTIFICATE-----\""
    )]
    UnterminatedBlock {
        /// Byte offset of the unmatched opening boundary.
        offset: usize,
    },

    /// A visible, non-ignorable character sits *outside* any block — before the first, between two,
    /// or after the last. A NUL, a BOM or stray whitespace there is dropped (it cannot carry or
    /// change a certificate); anything else is real data this parser cannot account for, so it is
    /// named and refused rather than skipped past.
    #[error(
        "the bytes outside the certificate blocks contain {character} at byte offset {offset}, \
         which is neither a PEM block nor ignorable whitespace; it was left in place rather than \
         guessed at"
    )]
    JunkOutsideBlocks {
        /// The offending character in `U+XXXX` notation — never the raw character.
        character: String,
        /// Byte offset in the response text.
        offset: usize,
    },

    /// A character inside a block's base64 body that is neither base64 nor the RFC 7468 line-wrap
    /// whitespace. Refused, never stripped: inside `BEGIN`/`END` a NUL, a BOM or a smart quote is
    /// corruption of the bytes the signing key decodes from, and massaging it away could hand back a
    /// different key. Only framing *outside* the blocks is safe to strip.
    #[error(
        "certificate block {index} contains {character} at byte offset {offset} inside its base64 \
         body, which is neither base64 nor whitespace; the payload is corrupt and was refused rather \
         than repaired"
    )]
    IllegalCharacterInBody {
        /// Which block (0-based), so a chain failure names the offending certificate.
        index: usize,
        /// The offending character in `U+XXXX` notation.
        character: String,
        /// Byte offset in the response text.
        offset: usize,
    },

    /// A block's body was all base64 characters and still did not decode. Not re-padded.
    #[error("certificate block {index} is not valid base64: {detail}")]
    Base64Invalid {
        /// Which block (0-based).
        index: usize,
        /// The decoder's own message.
        detail: String,
    },

    /// A block decoded, and the bytes are not an X.509 certificate.
    #[error("certificate block {index} did not decode to an X.509 certificate: {detail}")]
    NotACertificate {
        /// Which block (0-based).
        index: usize,
        /// The DER reader's own message.
        detail: String,
    },
}

impl From<CertificateChainError> for CmdError {
    fn from(err: CertificateChainError) -> Self {
        // One message shape for every chain defect, so the stable error code the API attaches
        // (`cmd_certificate_chain`) covers them all while the specific reason rides in the detail.
        CmdError::Certificate(format!("invalid certificate PEM chain: {err}"))
    }
}

/// Parse the PEM certificate chain a `GetCertificate` response carries into its DER blocks, in order
/// (leaf first, as AMA sends it), tolerating the transport junk a strict RFC 7468 reader rejects.
///
/// # Why a strict reader is the wrong tool here
///
/// The chain arrives as a JSON string value, and a real one has been observed carrying a **NUL byte
/// in the preamble** — the bytes before the first `-----BEGIN CERTIFICATE-----`. `x509-cert`'s
/// `Certificate::load_pem_chain` refuses the whole chain at that first NUL ("PEM preamble contains
/// invalid data (NUL byte)"), so a citizen's perfectly good certificate never reaches CMS assembly.
///
/// # The invariant: sanitise the framing, never the key bytes
///
/// The one thing this must never do is hand back a different key than AMA sent — on a signature
/// surface that is the worst possible failure, because the signing certificate is *selected out of
/// this chain* and a shifted byte selects the wrong key or a broken one. So the line is drawn by
/// **location**, not by character class:
///
/// - **Outside the blocks** — the preamble (before the first `BEGIN`), the epilogue (after the last
///   `END`), and the gaps between concatenated certificates — is armour and framing, not the base64
///   body. A NUL or other C0 control, a BOM, a CR, stray whitespace there provably cannot change one
///   bit of any decoded certificate, so it is stripped. A *visible* character out here is
///   unaccounted-for data, not framing, and is refused by name.
/// - **Inside a block body** — between `BEGIN` and `END` — the only thing dropped is the RFC 7468
///   line-wrapping (ASCII whitespace), which carries no base64 value. **Everything else is refused,
///   loudly.** A NUL, a BOM, a zero-width space or a smart quote *inside the body* is not junk to
///   strip: it means the payload the key decodes from is corrupt, and corrupt payload must fail, not
///   be massaged into something that parses. This is deliberately **stricter than the input side**
///   ([`normalize_ama_key_pem`], which reports and strips ignorable body characters for an operator's
///   pasted key): a machine response feeding a qualified signature gets no such benefit of the doubt.
///
/// This mirrors the working reference `recov-pt`, which splits on the `BEGIN`/`END` boundaries and
/// strips only whitespace from each body (a body NUL reaches its base64 decoder and fails there);
/// this refuses the same corruption one step earlier, naming the offending byte.
///
/// The proof that the stripping cannot move a key is a test, not a hope: a filthy chain and its clean
/// twin normalise to byte-identical DER and an identical SubjectPublicKeyInfo fingerprint, per
/// certificate and in the same order — see the `key_survives_*` tests.
pub(crate) fn normalize_response_cert_chain(
    input: &str,
) -> Result<Vec<Vec<u8>>, CertificateChainError> {
    let mut ders: Vec<Vec<u8>> = Vec::new();
    let mut cursor = 0usize;

    loop {
        let remainder = &input[cursor..];
        let next_begin = remainder.find(BEGIN_CERTIFICATE);
        // Everything from the cursor up to the next block (or end of input) is outside any block —
        // preamble, an inter-block gap, or the epilogue. It is framing: ignorable classes are
        // stripped, and a visible character here is unaccounted-for data, refused by name.
        let gap_end = next_begin.unwrap_or(remainder.len());
        for (offset, c) in remainder[..gap_end].char_indices() {
            if !is_ignorable_in_body(c) {
                return Err(CertificateChainError::JunkOutsideBlocks {
                    character: format!("U+{:04X}", c as u32),
                    offset: cursor + offset,
                });
            }
        }

        let Some(begin_rel) = next_begin else { break };
        let begin_at = cursor + begin_rel;
        let body_start = begin_at + BEGIN_CERTIFICATE.len();
        let body_len = input[body_start..]
            .find(END_CERTIFICATE)
            .ok_or(CertificateChainError::UnterminatedBlock { offset: begin_at })?;
        let body = &input[body_start..body_start + body_len];

        let index = ders.len();
        let mut base64_body = String::with_capacity(body.len());
        for (offset, c) in body.char_indices() {
            if c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=') {
                base64_body.push(c);
            } else if c.is_ascii_whitespace() {
                // The ONLY thing dropped inside a body: RFC 7468 line-wrapping (LF, CR, tab, space,
                // form feed). It carries no base64 value, so the decoded DER cannot move.
            } else {
                // Anything else inside the body is corruption of the key's own bytes, never framing
                // to strip — a NUL, a BOM, a zero-width space, a smart quote. Refuse it, named, so a
                // corrupt payload can never be quietly reshaped into a different key that parses.
                return Err(CertificateChainError::IllegalCharacterInBody {
                    index,
                    character: format!("U+{:04X}", c as u32),
                    offset: body_start + offset,
                });
            }
        }

        let der =
            STANDARD
                .decode(&base64_body)
                .map_err(|e| CertificateChainError::Base64Invalid {
                    index,
                    detail: e.to_string(),
                })?;
        // Validate that the decoded bytes really are an X.509 certificate before accepting them —
        // the raw decoded DER (what AMA actually sent, and what the signature is over) is kept, not
        // a re-encoding of it.
        Certificate::from_der(&der).map_err(|e| CertificateChainError::NotACertificate {
            index,
            detail: e.to_string(),
        })?;
        ders.push(der);

        cursor = body_start + body_len + END_CERTIFICATE.len();
    }

    if ders.is_empty() {
        return Err(CertificateChainError::NoCertificates);
    }
    Ok(ders)
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

    // --- The response side: GetCertificate's certificate chain ------------------------------------

    /// **Reproduce-then-fix.** The exact failure from the running app: a real chain carrying a NUL
    /// byte in the PEM preamble (and control/whitespace junk between the blocks). The strict reader
    /// the flow used before this fix refuses it outright; the tolerant parser recovers every
    /// certificate, byte-for-byte. Three concatenated copies of the one synthetic fixture stand in
    /// for the leaf + issuers chain — parsing does not verify issuer relationships, so this exercises
    /// the multi-block split without three distinct test certs.
    #[test]
    fn a_response_chain_with_a_nul_preamble_and_inter_block_junk_parses() {
        let one = CLEAN.trim_end();
        // NUL + BOM + spaces before the first block; a NUL, a CR/LF and a BEL between the blocks.
        let dirty = format!("\u{0}\u{FEFF}  {one}\n\u{0}\n{one}\r\n\u{0007}\n{one}\n\u{0}");

        // GUARD: the strict RFC 7468 reader the flow used before this fix must still reject the
        // dirty chain — otherwise this test would pass without proving the fix does anything.
        assert!(
            Certificate::load_pem_chain(dirty.as_bytes()).is_err(),
            "the strict reader must reject a NUL in the preamble, or this test proves nothing"
        );

        let ders = normalize_response_cert_chain(&dirty).expect("the dirty chain must normalise");
        assert_eq!(
            ders.len(),
            3,
            "all three concatenated certificates must be recovered"
        );
        let reference = reference_der();
        for (i, der) in ders.iter().enumerate() {
            assert_eq!(
                der, &reference,
                "certificate {i} decoded to different bytes"
            );
            // And every recovered block really is an X.509 certificate.
            assert!(
                Certificate::from_der(der).is_ok(),
                "certificate {i} is not valid X.509 DER"
            );
        }
    }

    /// A single clean certificate is a one-element chain, and its DER is exactly what a strict reader
    /// decodes — the tolerant path must not move the bytes of an already-clean response.
    #[test]
    fn a_clean_single_certificate_response_is_a_one_element_chain() {
        let ders = normalize_response_cert_chain(CLEAN).expect("a clean response normalises");
        assert_eq!(ders.len(), 1);
        assert_eq!(ders[0], reference_der());
    }

    /// A NUL, a BOM and whitespace between two blocks must not break the split — the reported
    /// preamble junk, moved between the certificates.
    #[test]
    fn junk_between_two_blocks_does_not_break_the_split() {
        let one = CLEAN.trim_end();
        let dirty = format!("{one}\u{0}\u{FEFF}\r\n\t{one}\n");
        let ders = normalize_response_cert_chain(&dirty).expect("inter-block junk is ignorable");
        assert_eq!(ders.len(), 2);
        assert_eq!(ders[0], reference_der());
        assert_eq!(ders[1], reference_der());
    }

    /// A response with no certificate block at all is refused by name, not returned empty; and a
    /// leading visible character is named rather than treated as an absent block.
    #[test]
    fn a_response_with_no_block_is_refused_by_name() {
        assert_eq!(
            normalize_response_cert_chain("\u{0}\u{FEFF}   \r\n").unwrap_err(),
            CertificateChainError::NoCertificates
        );
        assert_eq!(
            normalize_response_cert_chain("nothing to see here").unwrap_err(),
            CertificateChainError::JunkOutsideBlocks {
                character: "U+006E".to_owned(),
                offset: 0,
            },
        );
    }

    /// An opening boundary with no matching close is refused, and the offset locates it.
    #[test]
    fn an_unterminated_block_is_refused_with_its_offset() {
        let body = body_of(CLEAN, BEGIN_CERTIFICATE, END_CERTIFICATE);
        let truncated = format!("{BEGIN_CERTIFICATE}\n{body}\n");
        assert_eq!(
            normalize_response_cert_chain(&truncated).unwrap_err(),
            CertificateChainError::UnterminatedBlock { offset: 0 }
        );
    }

    /// A visible, non-ignorable character between blocks is real data this parser will not guess
    /// away: it is named and the chain is refused, never silently skipped.
    #[test]
    fn a_visible_character_outside_the_blocks_is_refused_not_skipped() {
        let one = CLEAN.trim_end();
        // A stray 'X' between the two blocks — not whitespace, not a control, not a block.
        let dirty = format!("{one}\nX\n{one}\n");
        match normalize_response_cert_chain(&dirty).unwrap_err() {
            CertificateChainError::JunkOutsideBlocks { character, offset } => {
                assert_eq!(character, "U+0058");
                assert_eq!(&dirty[offset..offset + 1], "X");
            }
            other => panic!("a visible inter-block character must be named, got {other:?}"),
        }
    }

    /// A character inside a body that would change the decoded bytes is refused by name and offset,
    /// exactly as the input side refuses a smart quote — dropping it would corrupt the certificate.
    #[test]
    fn an_illegal_character_in_a_body_is_refused_by_name() {
        let body = body_of(CLEAN, BEGIN_CERTIFICATE, END_CERTIFICATE);
        let corrupted = format!(
            "{BEGIN_CERTIFICATE}\n\u{201C}{}\n{END_CERTIFICATE}\n",
            &body[1..]
        );
        match normalize_response_cert_chain(&corrupted).unwrap_err() {
            CertificateChainError::IllegalCharacterInBody {
                index,
                character,
                offset,
            } => {
                assert_eq!(index, 0);
                assert_eq!(character, "U+201C");
                assert_eq!(&corrupted[offset..offset + 3], "\u{201C}");
            }
            other => panic!("a smart quote in the body must be named, got {other:?}"),
        }
    }

    /// A block whose base64 decodes cleanly but is not an X.509 certificate is refused, naming which
    /// block — a NUL that got past the preamble must never be mistaken for a valid chain.
    #[test]
    fn a_block_that_is_not_a_certificate_is_refused_naming_the_block() {
        let one = CLEAN.trim_end();
        let mixed = format!("{one}\n{BEGIN_CERTIFICATE}\nZm9v\n{END_CERTIFICATE}\n");
        match normalize_response_cert_chain(&mixed).unwrap_err() {
            CertificateChainError::NotACertificate { index, .. } => assert_eq!(index, 1),
            other => panic!("the second block is not a certificate, got {other:?}"),
        }
    }

    /// A CmdError built from a chain failure keeps the historical "invalid certificate PEM chain:"
    /// prefix, so the stable code the API attaches covers every chain defect under one sentence.
    #[test]
    fn a_chain_error_maps_to_a_cmd_certificate_error_with_the_stable_prefix() {
        let err: CmdError = CertificateChainError::NoCertificates.into();
        match err {
            CmdError::Certificate(msg) => {
                assert!(msg.starts_with("invalid certificate PEM chain:"), "{msg}");
            }
            other => panic!("a chain error must become CmdError::Certificate, got {other:?}"),
        }
    }

    // --- Key integrity: sanitise the framing, never the key -----------------------------------------

    /// A SECOND, distinct synthetic self-signed certificate — a different RSA-2048 key from [`CLEAN`],
    /// so a chain built from the two has a leaf and an issuer told apart by their key. Generated with
    /// `openssl req -x509 -newkey rsa:2048` (CN=CMD Test Issuer, O=Encosto Estratégico Lda); no real
    /// AMA material. Its whole purpose is the leaf-selection proof: if sanitisation could shift a
    /// byte, the wrong certificate would present as the leaf and the signature would verify against
    /// nothing.
    const DISTINCT_ISSUER_CERT: &str = r"-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIUMfqjQfNHZyWjGCBrrvkbShuP2p0wDQYJKoZIhvcNAQEL
BQAwSTELMAkGA1UEBhMCUFQxIDAeBgNVBAoMF0VuY29zdG8gRXN0cmF0ZWdpY28g
TGRhMRgwFgYDVQQDDA9DTUQgVGVzdCBJc3N1ZXIwHhcNMjYwNzMxMTcwMjI5WhcN
MzYwNzI4MTcwMjI5WjBJMQswCQYDVQQGEwJQVDEgMB4GA1UECgwXRW5jb3N0byBF
c3RyYXRlZ2ljbyBMZGExGDAWBgNVBAMMD0NNRCBUZXN0IElzc3VlcjCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMqYz5cpHnm50BzFmnvAz0koggQiU/qx
GMK94T9BuMmRh21KvJ3FlsPymqvdWa+4Mno/7QhUKKSCDZxdFL0i3xfK62XHrnps
dXqc9MeVbegD7AYxXRO9u38qayx0C+8GkxZotEdgRciklFb9j58xOZwthdMbObYa
JyuKC/U6KLkwskhLB3DEbHIC1HniSQCLZAFxGN/LglizA+Xx4RrWsa9p9UZCBcz8
QKRk7Lh4DNjgD9Y+4+1P8Yl3EN8XJ49LLEe59e50VvL5dA2oBC7rJgbvg3xbzG8A
CycQSUQnlAiUJN2rhZr0MeEQa5INdaQgAyPOirhRRHB68xLJwwGqjdMCAwEAAaNT
MFEwHQYDVR0OBBYEFN7cz0K0w8Wa0eQIQ7BXM3lrdr+qMB8GA1UdIwQYMBaAFN7c
z0K0w8Wa0eQIQ7BXM3lrdr+qMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAHXy4atfD7lp2ogzhWR5Bq3wBpT0Jz/G+Uv4jIMxrcQGIGXrhazPLlKV
fnXnx5Z3WGiYW1ozj/ZjB8rAKptSBUqgrlQbgM7JRPoMXHmOA0rwCBqPsH3zzgwm
yaP4z+U/Xgsa9ilsnspLlJDI3zhUqWi4xzVqTsOtW5eAzMaIN1MrQCslkSijyGJK
usydaCbOvB9YBdWlDVlDBYjnY7wklFhLHTWenOl7O40h9qNCypzeDwX23/jXsMKr
T9qeDRk3lSowd3xvYfbCUK7O6PvrbI+zoljKHuuEURgq6/vZu+SGd522nn1zQrGe
vDFQV1saFhFNm2jzZw6GkbIGqSVYaoU=
-----END CERTIFICATE-----
";

    /// The SHA-256 fingerprint of a decoded certificate's `SubjectPublicKeyInfo` — the public key
    /// inside it, independent of the framing around it. Computed the same way the input side's
    /// [`NormalizedAmaKeyPem::public_key_sha256_fingerprint`] is, so a certificate and its bare key
    /// fingerprint alike.
    fn spki_fingerprint_of(cert_der: &[u8]) -> String {
        let cert = Certificate::from_der(cert_der).expect("a decoded chain cert is valid X.509");
        let spki = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("its SubjectPublicKeyInfo re-encodes");
        hex_sha256(&spki)
    }

    /// A filthy copy of a two-cert chain: NUL+BOM+spaces preamble, NUL/CRLF/BEL between the blocks,
    /// and BOM+NUL epilogue — every byte of it outside the base64 bodies.
    fn filthy_two_cert_chain(leaf: &str, issuer: &str) -> String {
        format!(
            "\u{0}\u{FEFF}  {}\r\n\u{0}\u{0007}\n{}\n\u{FEFF}\u{0}",
            leaf.trim_end(),
            issuer.trim_end(),
        )
    }

    /// **The key-integrity proof, single certificate.** A filthy copy and its clean twin normalise to
    /// byte-identical DER *and* an identical public-key fingerprint. This is the same guarantee the
    /// input side makes for a pasted key, made here for the response path because the signing key is
    /// selected out of this chain.
    #[test]
    fn key_survives_sanitisation_byte_for_byte_for_one_certificate() {
        let clean = normalize_response_cert_chain(CLEAN).unwrap();
        let filthy_src = format!("\u{0}\u{FEFF}\r\n{}\n\u{0}", CLEAN.trim_end());
        let filthy = normalize_response_cert_chain(&filthy_src).unwrap();

        assert_eq!(clean.len(), 1);
        assert_eq!(filthy.len(), 1);
        // The decoded DER — the bytes the signature is over — did not move.
        assert_eq!(filthy[0], clean[0]);
        assert_eq!(filthy[0], reference_der());
        // Nor did the public key inside it, checked against the module's independent SPKI reference.
        assert_eq!(
            spki_fingerprint_of(&filthy[0]),
            spki_fingerprint_of(&clean[0])
        );
        assert_eq!(
            spki_fingerprint_of(&filthy[0]),
            hex_sha256(&reference_spki_der())
        );
    }

    /// **The key-integrity proof, and leaf selection, across a DISTINCT chain.** The leaf and issuer
    /// carry different keys, so this can prove the thing that matters most: sanitising the framing
    /// neither changes which certificate is the leaf nor the key it carries. If normalisation could
    /// shift a byte, the leaf's fingerprint would move — and `flow.rs` selects index 0 as the signing
    /// certificate, so a shifted leaf is a signature that verifies against nothing.
    #[test]
    fn key_survives_and_leaf_selection_holds_across_a_distinct_chain() {
        let clean = normalize_response_cert_chain(&format!(
            "{}\n{}\n",
            CLEAN.trim_end(),
            DISTINCT_ISSUER_CERT.trim_end()
        ))
        .unwrap();
        assert_eq!(clean.len(), 2);
        let clean_leaf_fp = spki_fingerprint_of(&clean[0]);
        let clean_issuer_fp = spki_fingerprint_of(&clean[1]);
        // The two certs genuinely carry different keys, or the leaf-selection proof below is vacuous.
        assert_ne!(
            clean_leaf_fp, clean_issuer_fp,
            "the leaf and issuer must have distinct keys for this proof to mean anything"
        );
        assert_eq!(
            clean_leaf_fp,
            hex_sha256(&reference_spki_der()),
            "the leaf is the CLEAN fixture's key"
        );

        let filthy =
            normalize_response_cert_chain(&filthy_two_cert_chain(CLEAN, DISTINCT_ISSUER_CERT))
                .unwrap();
        assert_eq!(
            filthy.len(),
            2,
            "sanitising the framing must not drop or add a certificate"
        );
        // Order preserved, bytes preserved, keys preserved — position by position.
        assert_eq!(filthy[0], clean[0]);
        assert_eq!(filthy[1], clean[1]);
        assert_eq!(spki_fingerprint_of(&filthy[0]), clean_leaf_fp);
        assert_eq!(spki_fingerprint_of(&filthy[1]), clean_issuer_fp);
        // The direction the sharpening is about: after sanitisation the LEAF still carries the leaf's
        // key, never the issuer's. `flow.rs::parse_cert_chain` takes `ders.remove(0)` as the signing
        // certificate, so this is exactly the key the signature is built against.
        assert_ne!(
            spki_fingerprint_of(&filthy[0]),
            clean_issuer_fp,
            "sanitisation must never let the issuer present as the leaf"
        );
    }

    /// A control byte, a BOM or a zero-width space **inside a body** is corruption of the key's own
    /// bytes, and is refused — never stripped like the preamble framing. This is the line the
    /// sharpening draws: outside the blocks such bytes are armour and are removed; inside them they
    /// mean the payload is wrong, and a signature surface fails rather than massages it into a
    /// different key that parses.
    #[test]
    fn a_control_byte_inside_a_body_is_refused_not_stripped() {
        let body = body_of(CLEAN, BEGIN_CERTIFICATE, END_CERTIFICATE);
        let corrupt = format!(
            "{BEGIN_CERTIFICATE}\n{}\u{0}{}\n{END_CERTIFICATE}\n",
            &body[..8],
            &body[8..]
        );
        match normalize_response_cert_chain(&corrupt).unwrap_err() {
            CertificateChainError::IllegalCharacterInBody {
                index, character, ..
            } => {
                assert_eq!(index, 0);
                assert_eq!(character, "U+0000");
            }
            other => panic!("a NUL inside the body must be refused, not stripped, got {other:?}"),
        }
        // A BOM and a zero-width space inside the body are refused the same way — the input side
        // would strip these, but the response body must not be touched.
        for junk in ['\u{FEFF}', '\u{200B}'] {
            let corrupt = format!(
                "{BEGIN_CERTIFICATE}\n{}{junk}{}\n{END_CERTIFICATE}\n",
                &body[..8],
                &body[8..]
            );
            assert!(
                matches!(
                    normalize_response_cert_chain(&corrupt),
                    Err(CertificateChainError::IllegalCharacterInBody { .. })
                ),
                "a {junk:?} inside the body must be refused, not stripped"
            );
        }
    }
}
