//! `chancela-registry` — certidão permanente consultation by access code (spec LEG-20/21/22).
//!
//! This crate pulls a Portuguese company's (or foundation's) registered data into Chancela from a
//! **certidão permanente access code** (the 12-digit `XXXX-XXXX-XXXX` código de acesso). The
//! certidão is not a structured API: it is an HTML certificate rendered from the access code, so
//! the crate fetches that HTML and parses it **defensively off the legally-stable Portuguese field
//! labels** (mirroring `chancela-tsl`'s "match local names, tolerate optional elements"
//! temperament) into a typed [`RegistryExtract`].
//!
//! # Pipeline
//! 1. [`AccessCode`] validates & normalizes the código de acesso. The full code is a **secret**:
//!    `Debug` renders it masked, and only [`AccessCode::expose_secret`] yields the full digits —
//!    used solely by the transport to build the request URL (LEG-22 / GDPR).
//! 2. [`RegistryTransport`] fetches the raw certidão — [`HttpRegistryTransport`] over blocking
//!    reqwest, [`MockRegistryTransport`] from canned fixtures.
//! 3. [`parse_certidao`] turns the HTML into a [`RegistryExtract`] (matrícula/NIPC, firma, forma
//!    jurídica, sede, CAE, objeto, capital, data de constituição, órgãos, and the ordered
//!    inscrições/averbamentos event feed for DOC-30), skipping unknown or optional sections rather
//!    than failing.
//! 4. [`RegistryClient`] ties transport + parse together into a one-call `lookup`.
//!
//! # Scope (this phase)
//! v1 is **read-only** (AI-31): we consult, never file. HTML only — PDF parsing is out of scope.
//! The live endpoint/params are validated only behind the `network-tests` feature against a real,
//! user-supplied access code (see `TESTING.md`).

pub mod client;
pub mod code;
pub mod error;
pub mod inscription;
pub mod mock;
pub mod model;
pub mod parse;
pub mod transport;

pub use client::RegistryClient;
pub use code::AccessCode;
pub use error::RegistryError;
pub use mock::MockRegistryTransport;
pub use model::{
    Address, AmendmentPayload, Apresentacao, CaeRef, CaeRole, CessationPayload,
    ConstitutionPayload, DesignationPayload, InscriptionDetail, InscriptionPayload, LegalForm,
    Money, Organ, OrganMember, Person, Quota, RegistryAnnotation, RegistryEvent, RegistryExtract,
    RegistryOfficer, RegistryOfficialSignature, RegistryProvenance,
};
pub use parse::parse_certidao;
pub use transport::{
    DEFAULT_REGISTRY_URL, ENV_REGISTRY_EMAIL, ENV_REGISTRY_TEST_CODE, ENV_REGISTRY_URL,
    HttpRegistryTransport, RegistryDocument, RegistryTransport,
};
